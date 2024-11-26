// ------------------------------------------------------------------------
// Insert Categories for CAPECs
UNWIND [capecCategoryFilesToImport] AS files

CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS category RETURN category',
  '
    MERGE (c:CAPEC {Name: "CAPEC-" + category.ID})
    SET c.Extended_Name = category.Name,
    c.Status = category.Status,
    c.Summary = toString(category.Summary),
    c.Note_Text = toStringList(apoc.convert.toList(category.Notes.Note.text)),
    c.Note_Type  = toString(category.Notes.Note.Type),
    c.Submission_Name = category.Content_History.Submission.Submission_Name,
    c.Submission_Date = category.Content_History.Submission.Submission_Date,
    c.Submission_Organization = category.Content_History.Submission.Submission_Organization,
    c.Modification_Name = [value IN category.Content_History.Modification | value.Modification_Name],
    c.Modification_Organization = [value IN category.Content_History.Modification | value.Modification_Organization],
    c.Modification_Date = [value IN category.Content_History.Modification | value.Modification_Date],
    c.Modification_Comment = [value IN category.Content_History.Modification | value.Modification_Comment]

    // Insert Members for each Category
    WITH c, category
    FOREACH (members IN category.Relationships.Has_Member |
      MERGE (MemberAP:CAPEC {Name: "CAPEC-" + members.CAPEC_ID})
      MERGE (c)-[:hasMember]->(MemberAP)
    )

    WITH c, category
    FOREACH (categoryExReference IN category.References.Reference |
      MERGE (catRef:External_Reference_CAPEC {Reference_ID: categoryExReference.External_Reference_ID})
      MERGE (c)-[rel:hasExternal_Reference]->(catRef)
      SET rel.Section = categoryExReference.Section
    )
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;