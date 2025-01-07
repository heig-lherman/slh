//! Stockage des données en mémoire, avec sauvegarde en JSON

use crate::{
    models::{MedicalReport, ReportID, UserData, UserID},
    utils::input_validation::Username,
};
use log::info;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, ErrorKind::NotFound},
    path::PathBuf,
};
use thiserror::Error;

// DO NOT MODIFY THIS FILE!!!

#[derive(Serialize, Deserialize, Default)]
pub struct Database {
    #[serde(skip)]
    path: Option<PathBuf>,
    users: HashMap<UserID, UserData>,
    reports: HashMap<ReportID, MedicalReport>,
}

#[derive(Debug, Error)]
pub enum DBError {
    #[error("Invalid user ID: {0}")]
    InvalidUserID(UserID),
    #[error("User already exists: {username}")]
    UserAlreadyExists { username: Username },
}

impl Database {
    pub fn open(path: PathBuf) -> Result<Self, io::Error> {
        match File::open(&path) {
            // File successfuly opened
            Ok(f) => {
                let mut db: Self = serde_json::from_reader(f)?;
                db.path = Some(path);
                Ok(db)
            }

            // Fichier non existant, on le crée
            Err(not_found) if not_found.kind() == NotFound => {
                info!("DB file not found, creating new empty DB");
                let mut new_db = Database::default();
                new_db.path = Some(path);

                // On vérifie la sauvegarde immédiatement pour diminuer le risque de perte de données
                new_db.save()?;
                Ok(new_db)
            }

            // Autre erreur d'IO, on s'arrête
            Err(other) => Err(other),
        }
    }

    pub fn save(&self) -> Result<(), io::Error> {
        if let Some(path) = &self.path {
            let file = File::create(path)?;
            serde_json::to_writer_pretty(file, self)?;
        }
        Ok(())
    }

    pub fn get_user(&self, user: UserID) -> Result<&UserData, DBError> {
        self.users.get(&user).ok_or(DBError::InvalidUserID(user))
    }

    pub fn get_user_mut(&mut self, user: UserID) -> Result<&mut UserData, DBError> {
        self.users
            .get_mut(&user)
            .ok_or(DBError::InvalidUserID(user))
    }

    pub fn lookup_username(&self, name: &Username) -> Option<&UserData> {
        self.users.values().find(|user| &user.username == name)
    }

    pub fn store_user(&mut self, data: UserData) {
        self.users.insert(data.id, data);
    }

    pub fn get_report(&self, report: ReportID) -> Option<&MedicalReport> {
        self.reports.get(&report)
    }

    pub fn get_report_data_mut(&mut self, report: ReportID) -> Option<&mut String> {
        Some(&mut self.reports.get_mut(&report)?.content)
    }

    pub fn store_report(&mut self, report: MedicalReport) {
        self.reports.insert(report.id, report);
    }

    pub fn list_reports(&self) -> impl Iterator<Item = &MedicalReport> + '_ {
        self.reports.values()
    }

    pub fn remove_reports(&mut self, patient: UserID) {
        self.reports.retain(|_id, report| report.patient != patient);
    }

    pub fn get_patients(&self, doctor: UserID) -> impl Iterator<Item = UserID> + '_ {
        self.users
            .values()
            .filter(move |u| u.has_doctor(doctor))
            .map(|u| u.id)
    }
}
