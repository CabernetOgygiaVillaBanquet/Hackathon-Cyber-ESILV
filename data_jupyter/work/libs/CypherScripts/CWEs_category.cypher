/ ------------------------------------------------------------------------
// Insert Categories for CWEs
UNWIND [cweCategoryFilesToImport] AS files
CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS category RETURN category',
  '
    MERGE (c:CWE {
      Name: "CWE-" + category.ID
    })
    SET c.Extended_Name = category.Name,
    c.Status = category.Status,
    c.Summary = toString(category.Summary),
    c.Note_Text = CASE apoc.meta.cypher.type (category.Notes.Note)
      WHEN "MAP" THEN toStringList(apoc.convert.toList(category.Notes.Note.text))
      WHEN "LIST OF MAP" THEN [value in category.Notes.Note WHERE value.text IS NOT NULL | value.text]
      ELSE null END,
    c.Note_Type  = CASE apoc.meta.cypher.type (category.Notes.Note)
      WHEN "MAP" THEN toStringList(apoc.convert.toList(category.Notes.Note.Type))
      WHEN "LIST OF MAP" THEN [value in category.Notes.Note | value.Type]
      ELSE null END,
    c.Submission_Name = category.Content_History.Submission.Submission_Name,
    c.Submission_Date = category.Content_History.Submission.Submission_Date,
    c.Submission_Organization = category.Content_History.Submission.Submission_Organization,
    c.Modification_Name = [value IN category.Content_History.Modification WHERE value.Modification_Name IS NOT NULL| value.Modification_Name],
    c.Modification_Organization = [value IN category.Content_History.Modification WHERE value.Modification_Organization IS NOT NULL | value.Modification_Organization],
    c.Modification_Date = [value IN category.Content_History.Modification WHERE value.Modification_Date IS NOT NULL | value.Modification_Date],
    c.Modification_Comment = [value IN category.Content_History.Modification WHERE value.Modification_Comment IS NOT NULL| value.Modification_Comment]

    // Insert Members for each Category
    WITH c, category
    FOREACH (member IN category.Relationships.Has_Member |
      MERGE (MemberWeak:CWE {Name: "CWE-" + member.CWE_ID})
      MERGE (c)-[:hasMember {ViewID: member.View_ID}]->(MemberWeak)
    )

    // ------------------------------------------------------------------------
    // Insert Public References for each Category
    WITH c, category
    FOREACH (categoryExReference IN category.References.Reference |
      MERGE (catRef:External_Reference_CWE {Reference_ID: categoryExReference.External_Reference_ID})
      MERGE (c)-[:hasExternal_Reference]->(catRef)
    )
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;