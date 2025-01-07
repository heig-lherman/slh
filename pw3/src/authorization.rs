//! Wrapper d'appel à Casbin pour la vérification statique
//! des conventions objet-action

use casbin::CoreApi;
use log::{error, info};
use serde::Serialize;
use serde_json::json;
use thiserror::Error;

use crate::models::{MedicalReport, Role, UserData};

const CONFIG: &str = "access_control/model.conf";
const POLICY: &str = "access_control/policy.csv";

/// Un enforcer Casbin
pub struct Enforcer(casbin::Enforcer);

type CasbinResult = Result<(), AccessDenied>;

/// Une erreur sans détails en cas d'accès refusé
#[derive(Debug, Error)]
#[error("Accès refusé.")]
pub struct AccessDenied;

/// Un contexte contenant une référence à un enforcer et à un sujet.
pub struct Context<'ctx> {
    enforcer: &'ctx Enforcer,
    subject: &'ctx UserData,
}

impl Enforcer {
    pub fn load() -> Result<Self, casbin::Error> {
        let mut enforcer = futures::executor::block_on(casbin::Enforcer::new(CONFIG, POLICY))?;
        futures::executor::block_on(enforcer.load_policy())?;
        Ok(Enforcer(enforcer))
    }

    pub fn with_subject<'ctx>(&'ctx self, subject: &'ctx UserData) -> Context<'ctx> {
        Context {
            enforcer: self,
            subject,
        }
    }
}

impl Context<'_> {
    fn enforce<O>(&self, object: O, action: &str) -> CasbinResult
    where
        O: Serialize + std::fmt::Debug + std::hash::Hash,
    {
        let subject = self.subject;

        info!(
            "Enforcing {}",
            json!({ "sub": subject, "obj": &object, "act": action })
        );
        match self.enforcer.0.enforce((subject, &object, action)) {
            Err(e) => {
                error!("Casbin error: {e:?}");
                Err(AccessDenied)
            }
            Ok(r) => {
                info!("Granted: {r}");
                if r {
                    Ok(())
                } else {
                    Err(AccessDenied)
                }
            }
        }
    }

    pub fn read_data(&self, patient: &UserData) -> CasbinResult {
        self.enforce(patient, "read-data")
    }

    pub fn update_data(&self, target: &UserData) -> CasbinResult {
        self.enforce(target, "update-data")
    }

    pub fn delete_data(&self, target: &UserData) -> CasbinResult {
        self.enforce(target, "delete-data")
    }

    pub fn add_report(&self, patient: &UserData, report: &MedicalReport) -> CasbinResult {
        self.enforce(
            json!({ "patient": patient, "report": report }),
            "add-report",
        )
    }

    // TODO can't check for doctor policy without having the patient ?
    pub fn read_report(&self, report: &MedicalReport) -> CasbinResult {
        self.enforce(report, "read-report")
    }

    pub fn update_report(&self, report: &MedicalReport) -> CasbinResult {
        self.enforce(report, "update-report")
    }

    pub fn update_role(&self, target: &UserData, role: Role) -> CasbinResult {
        self.enforce(json!({ "target": target, "role": role }), "update-role")
    }

    pub fn add_doctor(&self, target: &UserData, doctor: &UserData) -> CasbinResult {
        self.enforce(json!({"patient": target, "doctor": doctor}), "add-doctor")
    }

    pub fn remove_doctor(&self, target: &UserData, doctor: &UserData) -> CasbinResult {
        self.enforce(
            json!({"patient": target, "doctor": doctor}),
            "remove-doctor",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BloodType, MedicalFolder, PersonalData, ReportID, UserID};
    use crate::utils::input_validation::{AVSNumber, Username};
    use crate::utils::password_utils::hash;
    use itertools::Itertools;
    use std::collections::BTreeSet;
    use test_log::test;

    // Helper functions to create test data
    fn create_user(role: Role, has_folder: bool) -> UserData {
        let medical_folder = if has_folder {
            Some(MedicalFolder {
                personal_data: PersonalData {
                    avs_number: AVSNumber::try_from("756.9926.8230.54").unwrap(),
                    blood_type: BloodType::A,
                },
                doctors: BTreeSet::new(),
            })
        } else {
            None
        };

        UserData {
            id: UserID::new(),
            role,
            username: Username::try_from("test_user").unwrap(),
            password: hash("password"),
            medical_folder,
        }
    }

    fn create_report(author: &UserData, patient: &UserData) -> MedicalReport {
        MedicalReport {
            id: ReportID::new(),
            title: "Test Report".to_string(),
            author: author.id,
            patient: patient.id,
            content: "Test content".to_string(),
        }
    }

    // Test cases generator
    // fn generate_test_cases() -> Vec<(UserData, UserData, MedicalReport)> {
    //     let roles = vec![Role::Admin, Role::Doctor, Role::Patient];
    //     let folder_options = vec![true, false];
    //     let doctor_options = vec![true, false]; // Whether to add the actor as a doctor
    //
    //     // Generate all possible combinations of actors (subjects)
    //     let actors = roles
    //         .iter()
    //         .cartesian_product(&folder_options)
    //         .map(|(&role, &has_folder)| create_user(role, has_folder));
    //
    //     // Generate all possible combinations of targets (objects)
    //     let targets = roles
    //         .iter()
    //         .cartesian_product(&folder_options)
    //         .cartesian_product(&doctor_options)
    //         .map(|((role, has_folder), has_doctor)| (*role, *has_folder, *has_doctor));
    //
    //     // Cross join actors and targets
    //     actors
    //         .cartesian_product(targets)
    //         .flat_map(|(actor, (target_role, target_has_folder, add_doctor))| {
    //             let mut target = create_user(target_role, target_has_folder);
    //
    //             // Add the actor as a doctor if conditions are met:
    //             // 1. target has a medical folder
    //             // 2. add_doctor is true
    //             // 3. actor is a doctor
    //             if target_has_folder && add_doctor && actor.role == Role::Doctor {
    //                 if let Some(folder) = &mut target.medical_folder {
    //                     folder.doctors.insert(actor.id);
    //                 }
    //             }
    //
    //             // Generate multiple reports to test different scenarios
    //             vec![
    //                 // Report by actor
    //                 (
    //                     actor.clone(),
    //                     target.clone(),
    //                     create_report(&actor, &target)
    //                 ),
    //                 // Report by target
    //                 (
    //                     actor.clone(),
    //                     target.clone(),
    //                     create_report(&target, &target)
    //                 ),
    //                 // Report by another doctor
    //                 (
    //                     actor.clone(),
    //                     target.clone(), {
    //                         let other_doctor = create_user(Role::Doctor, false);
    //                         create_report(&other_doctor, &target)
    //                     }
    //                 ),
    //             ]
    //         })
    //         .collect()
    // }
    fn generate_test_cases() -> Vec<(UserData, UserData, MedicalReport)> {
        let mut cases = Vec::new();

        // Create our base users
        let admin = create_user(Role::Admin, false);
        let admin_with_folder = create_user(Role::Admin, true);
        let doctor = create_user(Role::Doctor, false);
        let doctor_with_folder = create_user(Role::Doctor, true);
        let patient = create_user(Role::Patient, false);
        let patient_with_folder = create_user(Role::Patient, true);

        // Create additional doctors for relationships
        let treating_doctor = create_user(Role::Doctor, false);
        let another_doctor = create_user(Role::Doctor, false);

        // Create patients with different doctor relationships
        let mut patient_with_one_doctor = create_user(Role::Patient, true);
        let mut patient_with_multiple_doctors = create_user(Role::Patient, true);

        // Set up doctor relationships
        if let Some(folder) = &mut patient_with_one_doctor.medical_folder {
            folder.doctors.insert(treating_doctor.id);
        }
        if let Some(folder) = &mut patient_with_multiple_doctors.medical_folder {
            folder.doctors.insert(treating_doctor.id);
            folder.doctors.insert(another_doctor.id);
        }

        // Test cases for admin permissions
        // Admin accessing various user types
        for target in [
            &admin,
            &admin_with_folder,
            &doctor,
            &doctor_with_folder,
            &patient,
            &patient_with_folder,
            &patient_with_one_doctor,
            &patient_with_multiple_doctors,
        ] {
            // Admin reading/writing user data
            cases.push((admin.clone(), target.clone(), create_report(&admin, target)));
        }

        // Test cases for doctor permissions
        for doctor in [
            &doctor,
            &doctor_with_folder,
            &treating_doctor,
            &another_doctor,
        ] {
            // Doctor accessing their own data
            cases.push((
                doctor.clone(),
                doctor.clone(),
                create_report(doctor, doctor),
            ));

            // Doctor accessing patients they treat
            for patient in [&patient_with_one_doctor, &patient_with_multiple_doctors] {
                cases.push((
                    doctor.clone(),
                    patient.clone(),
                    create_report(doctor, patient),
                ));
                // Also test with reports created by others
                cases.push((
                    doctor.clone(),
                    patient.clone(),
                    create_report(&admin, patient),
                ));
                cases.push((
                    doctor.clone(),
                    patient.clone(),
                    create_report(patient, patient),
                ));
            }

            // Doctor accessing patients they don't treat
            cases.push((
                doctor.clone(),
                patient.clone(),
                create_report(doctor, &patient),
            ));
            cases.push((
                doctor.clone(),
                patient_with_folder.clone(),
                create_report(doctor, &patient_with_folder),
            ));
        }

        // Test cases for patient permissions
        for patient in [
            &patient,
            &patient_with_folder,
            &patient_with_one_doctor,
            &patient_with_multiple_doctors,
        ] {
            // Patient accessing own data
            cases.push((
                patient.clone(),
                patient.clone(),
                create_report(patient, patient),
            ));

            // Patient accessing reports about themselves
            cases.push((
                patient.clone(),
                patient.clone(),
                create_report(&treating_doctor, patient),
            ));

            // Patient trying to access other patients
            for other_patient in [&patient_with_folder, &patient_with_one_doctor] {
                if other_patient.id != patient.id {
                    cases.push((
                        patient.clone(),
                        other_patient.clone(),
                        create_report(&treating_doctor, other_patient),
                    ));
                }
            }
        }

        // Edge cases
        // Doctor who is also a patient (has medical folder)
        cases.push((
            doctor_with_folder.clone(),
            patient_with_one_doctor.clone(),
            create_report(&doctor_with_folder, &patient_with_one_doctor),
        ));

        // Admin who is also a patient
        cases.push((
            admin_with_folder.clone(),
            patient_with_one_doctor.clone(),
            create_report(&admin_with_folder, &patient_with_one_doctor),
        ));

        cases
    }

    #[test]
    fn test_read_data_permissions() {
        let enforcer = Enforcer::load().unwrap();

        for (actor, target, _) in generate_test_cases() {
            let context = enforcer.with_subject(&actor);
            let result = context.read_data(&target);

            // Admin can always read
            if actor.role == Role::Admin {
                assert!(
                    result.is_ok(),
                    "Admin {:?} should be able to read data of {:?}",
                    actor.role,
                    target.role
                );
                continue;
            }

            // Users can read their own data
            if actor.id == target.id {
                assert!(result.is_ok(), "User should be able to read their own data");
                continue;
            }

            // Doctors can read their patients' data
            if actor.role == Role::Doctor
                && target
                    .medical_folder
                    .as_ref()
                    .map_or(false, |f| f.doctors.contains(&actor.id))
            {
                assert!(
                    result.is_ok(),
                    "Doctor should be able to read their patient's data"
                );
                continue;
            }

            // All other cases should be denied
            assert!(
                result.is_err(),
                "Unexpected access granted: {:?} reading {:?}",
                actor.role,
                target.role
            );
        }
    }

    #[test]
    fn test_update_data_permissions() {
        let enforcer = Enforcer::load().unwrap();

        for (actor, target, _) in generate_test_cases() {
            let context = enforcer.with_subject(&actor);
            let result = context.update_data(&target);

            // Admin can always update
            if actor.role == Role::Admin {
                assert!(
                    result.is_ok(),
                    "Admin should be able to update any user's data"
                );
                continue;
            }

            // Users can update their own data
            if actor.id == target.id {
                assert!(
                    result.is_ok(),
                    "User should be able to update their own data"
                );
                continue;
            }

            // All other cases should be denied
            assert!(
                result.is_err(),
                "Unexpected update access granted: {:?} updating {:?}",
                actor.role,
                target.role
            );
        }
    }

    #[test]
    fn test_add_report_permissions() {
        let enforcer = Enforcer::load().unwrap();

        for (actor, target, report) in generate_test_cases() {
            let context = enforcer.with_subject(&actor);
            let result = context.add_report(&target, &report);

            // Admin can always add reports
            if actor.role == Role::Admin {
                assert!(
                    result.is_ok(),
                    "Admin should be able to add reports for any user"
                );
                continue;
            }

            // Doctors can add reports for users with medical folders
            if actor.role == Role::Doctor
                && report.author == actor.id
                && target.medical_folder.is_some()
            {
                assert!(
                    result.is_ok(),
                    "Doctor should be able to add reports for users with medical folders"
                );
                continue;
            }

            // All other cases should be denied
            assert!(
                result.is_err(),
                "Unexpected report creation access granted: {:?} for {:?}",
                actor.role,
                target.role
            );
        }
    }

    #[test]
    fn test_read_report_permissions() {
        let enforcer = Enforcer::load().unwrap();

        for (actor, target, report) in generate_test_cases() {
            let context = enforcer.with_subject(&actor);
            let result = context.read_report(&report);

            // Admin can always read reports
            if actor.role == Role::Admin {
                assert!(result.is_ok(), "Admin should be able to read any report");
                continue;
            }

            // Report authors can read their reports
            if actor.id == report.author {
                assert!(
                    result.is_ok(),
                    "Author should be able to read their own report"
                );
                continue;
            }

            // Doctors can read reports of their patients
            if actor.role == Role::Doctor
                && target
                    .medical_folder
                    .as_ref()
                    .map_or(false, |f| f.doctors.contains(&actor.id))
            {
                assert!(
                    result.is_ok(),
                    "Doctor should be able to read their patient's reports"
                );
                continue;
            }

            // All other cases should be denied
            assert!(
                result.is_err(),
                "Unexpected report read access granted: {:?} reading report by {:?}",
                actor.role,
                report.author
            );
        }
    }

    #[test]
    fn test_update_report_permissions() {
        let enforcer = Enforcer::load().unwrap();

        for (actor, _, report) in generate_test_cases() {
            let context = enforcer.with_subject(&actor);
            let result = context.update_report(&report);

            // Admin can always update reports
            if actor.role == Role::Admin {
                assert!(result.is_ok(), "Admin should be able to update any report");
                continue;
            }

            // Report authors can update their reports
            if actor.id == report.author {
                assert!(
                    result.is_ok(),
                    "Author should be able to update their own report"
                );
                continue;
            }

            // All other cases should be denied
            assert!(
                result.is_err(),
                "Unexpected report update access granted: {:?} updating report by {:?}",
                actor.role,
                report.author
            );
        }
    }

    #[test]
    fn test_doctor_management_permissions() {
        let enforcer = Enforcer::load().unwrap();

        for (actor, target, _) in generate_test_cases() {
            let context = enforcer.with_subject(&actor);
            let doctor = create_user(Role::Doctor, false);

            // Test add_doctor
            let add_result = context.add_doctor(&target, &doctor);
            // Test remove_doctor
            let remove_result = context.remove_doctor(&target, &doctor);

            // Admin can always manage doctors
            if actor.role == Role::Admin {
                assert!(
                    add_result.is_ok() && remove_result.is_ok(),
                    "Admin should be able to manage doctors for any user"
                );
                continue;
            }

            // Users can manage their own doctors
            if actor.id == target.id {
                assert!(
                    add_result.is_ok() && remove_result.is_ok(),
                    "User should be able to manage their own doctors"
                );
                continue;
            }

            // All other cases should be denied
            assert!(
                add_result.is_err() && remove_result.is_err(),
                "Unexpected doctor management access granted: {:?} managing doctors for {:?}",
                actor.role,
                target.role
            );
        }
    }

    // Additional helper tests
    #[test]
    fn test_medical_folder_helper_functions() {
        let mut folder = MedicalFolder::new(PersonalData {
            avs_number: AVSNumber::try_from("756.9926.8230.54").unwrap(),
            blood_type: BloodType::A,
        });

        let doctor_id = UserID::new();

        // Test empty folder
        assert!(!folder.doctors.contains(&doctor_id));

        // Test adding doctor
        folder.doctors.insert(doctor_id);
        assert!(folder.doctors.contains(&doctor_id));

        // Test removing doctor
        folder.doctors.remove(&doctor_id);
        assert!(!folder.doctors.contains(&doctor_id));
    }
}
