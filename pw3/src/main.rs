use anyhow::{anyhow, Result};
use derive_more::Display;
use inquire::{Confirm, Password, Select, Text};
use karak::authorization::Enforcer;
use karak::db::Database;
use karak::models::*;
use karak::services::Service;
use karak::utils::input_validation::{username_input_validation, AVSNumber};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

const DB_FILE: &str = "database.json";

// ---------------------------------- NE PAS MODIFIER -------------------------------------------

type MenuExit = Option<()>;
const MENU_EXIT: MenuExit = None;
const MENU_LOOP: MenuExit = Some(());

/// Représente un menu texte
trait Menu {
    /// Implémente le contenu du menu. La valeur de retour
    /// doit être None si le menu souhaite terminer,
    /// ou Some(()) s'il faut le relancer.
    fn enter(&mut self) -> Result<Option<()>>;

    /// Lance le menu en boucle, en interceptant les erreurs,
    /// sauf si le menu souhaite quitter.
    fn enter_loop(&mut self) {
        while let Some(result) = self.enter().transpose() {
            if let Err(error) = result {
                eprintln!("Erreur: {error}");
            }
        }
    }
}

pub struct App {
    service: Service,
}

impl App {
    pub fn new(service: Service) -> Self {
        App { service }
    }

    pub fn start(&mut self) -> Result<()> {
        println!("Bienvenue sur KARAK, le dossier électronique du patient super sécurisé.");
        self.enter_loop();
        self.service.save()?;
        Ok(())
    }
}

impl Menu for App {
    fn enter(&mut self) -> Result<MenuExit> {
        #[derive(EnumIter, Display)]
        enum Choice {
            #[display("Créer un compte")]
            Register,
            #[display("Se connecter")]
            Login,
            #[display("Quitter")]
            Exit,
        }

        let choice = Select::new("Que voulez-vous faire ?", Choice::iter().collect()).prompt()?;

        match choice {
            Choice::Register => {
                let username = username_input_validation("Username à enregistrer: ")?;
                self.service.register(username)?;
                Ok(MENU_LOOP) // Retourne au menu principal après l'enregistrement
            }
            Choice::Login => {
                let username = username_input_validation("Username: ")?;
                let password = Password::new("Entrez votre mot de passe : ")
                    .without_confirmation()
                    .with_display_mode(inquire::PasswordDisplayMode::Masked)
                    .prompt()?;

                let user_id = self.service.login(&username, &password)?;

                eprintln!("[*] Bienvenue, {}.", username);
                UserMenu {
                    service: &mut self.service,
                    user_id,
                }
                .enter_loop();
                Ok(MENU_LOOP)
            }
            Choice::Exit => Ok(MENU_EXIT),
        }
    }
}

struct UserMenu<'srv> {
    service: &'srv mut Service,
    user_id: UserID,
}

impl Menu for UserMenu<'_> {
    fn enter(&mut self) -> Result<Option<()>> {
        #[derive(EnumIter, Display)]
        enum Choice {
            #[display("Créer mon dossier médical")]
            SetPersonalData,

            #[display("Lire mon dossier médical")]
            ReadFolder,

            #[display("Donner accès à mon dossier à un médecin")]
            AddDoctor,

            #[display("Lire le dossier d'un patient")]
            CheckPatient,

            #[display("Écrire un rapport")]
            AddReport,

            #[display("Administrer les Rôles")]
            UpdateRole,

            #[display("Supprimer toutes mes données")]
            WipeAccount,

            #[display("Se déconnecter")]
            Logout,
        }

        let choice = Select::new("Que voulez-vous faire ?", Choice::iter().collect()).prompt()?;
        match choice {
            Choice::ReadFolder => {
                ReportsMenu {
                    service: self.service,
                    patient_id: self.user_id,
                }
                .show()?;
            }

            Choice::SetPersonalData => {
                let avs_number: AVSNumber =
                    Text::new("Entrez votre numéro AVS:").prompt()?.try_into()?;
                let blood_type =
                    Select::new("Entrez votre groupe sanguin:", BloodType::iter().collect())
                        .prompt()?;

                self.service.update_data(
                    self.user_id,
                    PersonalData {
                        avs_number,
                        blood_type,
                    },
                )?;
            }

            Choice::AddDoctor => {
                let username = username_input_validation("Username du médecin: ")?;

                if let Some(doctor) = self.service.lookup_user(&username) {
                    self.service.add_doctor(self.user_id, doctor)?;
                    println!("Ce médecin a maintenant accès a votre dossier");
                }
            }

            Choice::CheckPatient => {
                let patients: Vec<&UserData> = self.service.list_patients().collect();

                let patient_id = Select::new("Choisissez un patient:", patients).prompt()?.id;

                ReportsMenu {
                    service: self.service,
                    patient_id,
                }
                .enter_loop()
            }

            Choice::AddReport => {
                let patient = self
                    .service
                    .lookup_user(&username_input_validation("Username du patient:")?)
                    .ok_or(anyhow!("Patient inexistant"))?;

                let title = Text::new("Entrez le titre du rapport:").prompt()?;

                let content = inquire::Editor::new("Enter the report:").prompt()?;

                self.service
                    .add_report(self.user_id, patient, title, content)?;
            }

            Choice::WipeAccount => {
                if Confirm::new("VOULEZ-VOUS VRAIMENT EFFACER VOTRE COMPTE ?")
                    .with_help_message("Si vous effacez votre compte, toutes vos données médicales seront effacées.")
                    .prompt()? {
                        self.service.delete_data(self.user_id)?;
                    }
            }

            Choice::UpdateRole => {
                let username = username_input_validation("Username à administrer: ")?;

                let user_id = self
                    .service
                    .lookup_user(&username)
                    .ok_or(anyhow!("Utilisateur inconnu"))?;

                let role = Select::new("Nouveau rôle", Role::iter().collect()).prompt()?;

                self.service.update_role(user_id, role)?;
            }

            Choice::Logout => return Ok(MENU_EXIT),
        };
        Ok(MENU_LOOP)
    }
}

struct ReportsMenu<'srv> {
    service: &'srv mut Service,
    patient_id: UserID,
}

impl ReportsMenu<'_> {
    fn show(&mut self) -> Result<()> {
        if let Ok(user) = self.service.get_data(self.patient_id) {
            let UserData {
                role,
                username,
                medical_folder,
                ..
            } = user;
            let has_data = if medical_folder.is_some() {
                "oui"
            } else {
                "non"
            };
            println!("User: {username}\nRole: {role}\nDossier électronique: {has_data}");

            if let Some(folder) = medical_folder {
                let PersonalData {
                    avs_number,
                    blood_type,
                } = &folder.personal_data;
                println!("Numéro AVS: {avs_number}\nGroupe sanguin: {blood_type}");
            }
        } else {
            println!("[!] L'accès à ce dossier est restreint")
        }

        Ok(self.enter_loop())
    }
}

impl Menu for ReportsMenu<'_> {
    fn enter(&mut self) -> Result<Option<()>> {
        let reports: Vec<&MedicalReport> = self.service.list_reports(self.patient_id).collect();

        if reports.is_empty() {
            println!("[*] Il n'y a pas de rapports dans ce dossier");
            return Ok(MENU_EXIT);
        }

        let Some(report) = Select::new("Choisissez un rapport:", reports).prompt_skippable()?
        else {
            return Ok(MENU_EXIT);
        };

        println!(
            "\n[{}]\nTitre: {}\nAuteur: {}\n\n{}\n===============",
            report.id, report.title, report.author, report.content
        );

        Ok(MENU_LOOP)
    }
}

fn main() -> anyhow::Result<()> {
    simple_logging::log_to_file("./karak.log", log::LevelFilter::Info)?;

    let db = Database::open(DB_FILE.into())?;
    let enforcer = Enforcer::load()?;
    App::new(Service::new(db, enforcer)).start()
}
