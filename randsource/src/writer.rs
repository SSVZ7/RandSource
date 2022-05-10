
use csv::WriterBuilder;
use std::{error::Error, fs::OpenOptions, path::Path};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct TestResult {
    pub n: String,
    pub dkg_time: String,
    pub vuf_time: String,
}

impl TestResult {
    pub fn write_to_csv(record: TestResult, path: &str) -> Result<(), Box<dyn Error>> {
        let mut file_exists = false;
        if Path::new(path.clone()).exists(){
            file_exists = true;
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        let mut writer = WriterBuilder::new()
            .has_headers(!file_exists)
            .from_writer(file);
    
        writer.serialize(record)?;
        writer.flush()?;
        Ok(())
    }
}