use std::sync::Arc;

use arrow::error::ArrowError;
use arrow_array::RecordBatch;
use arrow_flight::FlightData;
use arrow_ipc::writer::{DictionaryTracker, EncodedData, IpcDataGenerator, IpcWriteOptions};
use arrow_schema::{Schema, SchemaRef};

/// Convert a `SchemaRef` -> single `FlightData` containing the schema IPC message.
pub fn flight_data_from_arrow_schema(schema: &SchemaRef) -> Result<FlightData, ArrowError> {
    let options = IpcWriteOptions::default();
    let mut tracker = DictionaryTracker::new(false); // don't error on replacement for streaming
    let data_gen = IpcDataGenerator::default();

    // returns EncodedData (ipc_message + optional arrow bytes)
    let encoded: EncodedData =
        data_gen.schema_to_bytes_with_dictionary_tracker(schema.as_ref(), &mut tracker, &options);

    // FlightData implements From<EncodedData>
    Ok(FlightData::from(encoded))
}

/// Encode one RecordBatch to Flight IPC: returns (main batch, dictionary batches).
/// Send dicts first, then the main batch.
pub fn flight_data_from_arrow_batch(
    batch: &RecordBatch,
) -> Result<(FlightData, Vec<FlightData>), ArrowError> {
    let options = IpcWriteOptions::default();
    let mut tracker = DictionaryTracker::new(false);
    let data_gen = IpcDataGenerator::default();

    // returns (Vec<EncodedData> dictionaries, EncodedData main_batch)
    let (dicts, main) = data_gen.encoded_batch(batch, &mut tracker, &options)?;

    Ok((
        FlightData::from(main),
        dicts.into_iter().map(FlightData::from).collect(),
    ))
}

/// Build FlightData sequence for a schema + list of RecordBatches.
/// Note: signature mirrors the arrow-flight helper you saw: (schema: &Schema, batches: Vec<RecordBatch>)
pub fn batches_to_flight_data(
    schema: &Schema,
    batches: Vec<RecordBatch>,
) -> Result<Vec<FlightData>, ArrowError> {
    // Schema -> Schema FlightData
    let schema_ref: SchemaRef = Arc::new(schema.clone());
    let mut out = Vec::new();
    out.push(flight_data_from_arrow_schema(&schema_ref)?);

    // Each RecordBatch -> possibly multiple FlightData (dicts + batch)
    for batch in batches {
        let (main_fd, mut parts) = flight_data_from_arrow_batch(&batch)?;
        parts.push(main_fd);

        out.append(&mut parts);
    }

    Ok(out)
}
