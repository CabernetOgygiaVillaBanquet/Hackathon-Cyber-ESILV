// ------------------------------------------------------------------------
// Insert Views for CWEs
UNWIND [cweViewFilesToImport] AS files
CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS view RETURN view',
  '
    MERGE (v:CWE_VIEW {ViewID: view.ID})
    SET v.Name = view.Name,
    v.Type = view.Type,
    v.Status = view.Status,
    v.Objective = toString(view.Objective),
    v.Filter = view.Filter,
    v.Note_Type = CASE apoc.meta.cypher.type (view.Notes.Note)
      WHEN "MAP" THEN toStringList(apoc.convert.toList(view.Notes.Note.Type))
      WHEN "LIST OF MAP" THEN [value in view.Notes.Note | value.Type]
      ELSE null END,
    v.Note_Text = CASE apoc.meta.cypher.type (view.Notes.Note)
        WHEN "MAP" THEN CASE 
                      WHEN apoc.map.get(view.Notes.Note,"text","def") = "def" THEN toStringList(apoc.convert.toList(view.Notes.Note.xhtml:p)) 
                      ELSE toStringList(apoc.convert.toList(view.Notes.Note.text)) 
                      END  
        WHEN "LIST OF MAP" THEN [value in view.Notes.Note WHERE value.text IS NOT NULL | value.text]
        ELSE null END,
    v.Submission_Name = view.Content_History.Submission.Submission_Name,
    v.Submission_Date = view.Content_History.Submission.Submission_Date,
    v.Submission_Organization = view.Content_History.Submission.Submission_Organization,
    v.Modification_Name = [value IN view.Content_History.Modification WHERE value.Modification_Name IS NOT NULL | value.Modification_Name],
    v.Modification_Organization = [value IN view.Content_History.Modification WHERE value.Modification_Organization IS NOT NULL| value.Modification_Organization],
    v.Modification_Date = [value IN view.Content_History.Modification WHERE value.Modification_Date IS NOT NULL| value.Modification_Date],
    v.Modification_Comment = [value IN view.Content_History.Modification WHERE value.Modification_Comment IS NOT NULL | value.Modification_Comment]

    // Insert Stakeholders for each View
    FOREACH (value IN view.Audience.Stakeholder |
      MERGE (st:Stakeholder {Type: value.Type})
      MERGE (v)-[rel:usefulFor]->(st)
      SET rel.Description = value.Description
    )

    // Insert Members for each View
    WITH v, view
    FOREACH (member IN view.Members.Has_Member |
      MERGE (MemberWeak:CWE {Name: "CWE-" + member.CWE_ID})
      MERGE (v)-[:hasMember]->(MemberWeak)
    )

    // ------------------------------------------------------------------------
    // Insert Public References for each View
    WITH v, view
    FOREACH (viewExReference IN view.References.Reference |
      MERGE (viewRef:External_Reference_CWE {Reference_ID: viewExReference.External_Reference_ID})
      MERGE (v)-[:hasExternal_Reference]->(viewRef)
    )
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;