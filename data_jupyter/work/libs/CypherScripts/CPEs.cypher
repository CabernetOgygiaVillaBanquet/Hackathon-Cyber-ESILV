UNWIND $cpeFilesToImport AS file
CALL apoc.periodic.iterate(
  '
  CALL apoc.load.json($file) YIELD value RETURN value, $file AS file
  ',
  '
    WITH value, file
    MERGE (cpe:CPE {
      uri: value.cpe23Uri
    })

    // Gérer les enfants CPE
    FOREACH (value_child IN value.cpe_name |
      MERGE (child:CPE {
        uri: value_child.cpe23Uri
      })
      MERGE (cpe)-[:parentOf]->(child)
    )
  ',
  {batchSize:1000, parallel: true, params: {file: file}}
) YIELD batches, total, timeTaken, committedOperations, failedOperations, failedBatches, retries, errorMessages, batch, operations, wasTerminated, failedParams, updateStatistics
RETURN batches, total, timeTaken, committedOperations, failedOperations, failedBatches, retries, errorMessages, batch, operations, wasTerminated, failedParams, updateStatistics;