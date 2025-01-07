//! Modèle de données

use std::collections::BTreeSet;

use derive_more::Display;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;
use uuid::Uuid;

use crate::utils::input_validation::{AVSNumber, Username};
use crate::utils::password_utils::PWHash;

/// Role d'un utilisateur: Médecin, Patient ou Admin
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Hash, EnumIter, Display)]
pub enum Role {
    Doctor,
    Patient,
    Admin,
}

/// Un groupe sanguin dans le système ABO
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Hash, EnumIter, Display)]
pub enum BloodType {
    A,
    AB,
    B,
    O,
}

/// Un identifiant unique d'utilisateur.
#[derive(
    Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord, Display,
)]
pub struct UserID(Uuid);

impl UserID {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

/// Un identifiant unique de rapport médical
#[derive(
    Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord, Display,
)]
pub struct ReportID(Uuid);

impl ReportID {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

/// Les données associées à un utilisateur.
///
/// Un utilisateur peut être un médecin ou un simple patient.
/// Un médecin dispose en plus d'une liste de patients.
///
/// Indépendamment de son rôle, un utilisateur peut avoir
/// un dossier médical, ou pas.
#[derive(Debug, Serialize, Deserialize, Hash, Display)]
#[display("{username}")]
pub struct UserData {
    pub id: UserID,
    pub role: Role,
    pub username: Username,
    pub password: PWHash,
    pub medical_folder: Option<MedicalFolder>,
}

impl UserData {
    pub fn has_doctor(&self, doctor: UserID) -> bool {
        self.medical_folder
            .as_ref()
            .map(|folder| folder.doctors.contains(&doctor))
            .unwrap_or(false)
    }
}

/// Le contenu d'un rapport médical
#[derive(Debug, Serialize, Deserialize, Hash, Display)]
#[display("{title}")]
pub struct MedicalReport {
    pub id: ReportID,
    pub title: String,
    pub author: UserID,
    pub patient: UserID,
    pub content: String,
}

/// Les données personnelles d'un patient
#[derive(Debug, Serialize, Deserialize, Hash)]
pub struct PersonalData {
    pub avs_number: AVSNumber,
    pub blood_type: BloodType,
}

/// Un dossier médical pour un patient donné.
/// Contient des données personnelles génériques,
/// une liste de rapports, et une liste
/// de médecins traitants autorisés.
#[derive(Debug, Serialize, Deserialize, Hash)]
pub struct MedicalFolder {
    pub personal_data: PersonalData,
    pub doctors: BTreeSet<UserID>,
}

impl MedicalFolder {
    pub fn new(personal_data: PersonalData) -> Self {
        Self {
            personal_data,
            doctors: BTreeSet::default(),
        }
    }
}
