// Insert CAPECs
UNWIND [capecAttackFilesToImport] AS files
CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS capec RETURN capec',
  '
    // Insert Attack Patterns for CAPECs
    MERGE (cp:CAPEC {
      Name: "CAPEC-" + capec.ID
    })
      SET cp.ExtendedName = capec.Name,
      cp.Abstraction = capec.Abstraction,
      cp.Status = capec.Status,
      cp.Description = toString(capec.Description),
      cp.Likelihood_Of_Attack = capec.Likelihood_Of_Attack,
      cp.Typical_Severity = capec.Typical_Severity,
      cp.Alternate_Terms = [value IN capec.Alternate_Terms.Alternate_Term | value.Term],
      cp.Prerequisites = [value IN capec.Prerequisites.Prerequisite | toString(value)],
      cp.Skills_Required = [value IN capec.Skills_Required.Skill | value.Level],
      cp.Skills_Required_Description = [value IN capec.Skills_Required.Skill | coalesce(toString(value.text), " NOT SET ")],
      cp.Mitigations = [value IN capec.Mitigations.Mitigation | toString(value)],
      cp.Examples = [value IN capec.Example_Instances.Example | toString(value)],
      cp.Note_Type = CASE apoc.meta.cypher.type (capec.Notes.Note)
        WHEN "MAP" THEN toStringList(apoc.convert.toList(capec.Notes.Note.Type))
        WHEN "LIST OF MAP" THEN [value in capec.Notes.Note | value.Type]
        ELSE null END,
      cp.Note_Text= CASE apoc.meta.cypher.type (capec.Notes.Note)
        WHEN "MAP" THEN toStringList(apoc.convert.toList(capec.Notes.Note.text))
        WHEN "LIST OF MAP" THEN [value in capec.Notes.Note | value.text]
        ELSE null END,
      cp.Submission_Date = capec.Content_History.Submission.Submission_Date,
      cp.Submission_Name = capec.Content_History.Submission.Submission_Name,
      cp.Submission_Organization = capec.Content_History.Submission.Submission_Organization,
      cp.Modification_Name = [value IN capec.Content_History.Modification | value.Modification_Name],
      cp.Modification_Organization = [value IN capec.Content_History.Modification | value.Modification_Organization],
      cp.Modification_Date = [value IN capec.Content_History.Modification | value.Modification_Date],
      cp.Modification_Comment = [value IN capec.Content_History.Modification  | value.Modification_Comment],
      cp.Resources_Required = [value IN capec.Resources_Required.Resource | toString(value)],
      cp.Indicators = [value IN capec.Indicators.Indicator | toString(value)]

    // Consequences
    FOREACH (consequence IN capec.Consequences.Consequence |
      MERGE (con:Consequence {Scope: [value IN consequence.Scope | value]})
      MERGE (cp)-[rel:hasConsequence]->(con)
      ON CREATE SET rel.Impact = [value IN consequence.Impact | value],
      rel.Note = consequence.Note,
      rel.Likelihood = consequence.Likelihood
    )

    // Mitigations
    FOREACH (mit IN capec.Mitigations.Mitigation |
      MERGE (m:Mitigation {
        Description: toString(mit)
      })
      MERGE (cp)-[:hasMitigation]->(m)
    )

    // Related Attack Patterns
    WITH cp, capec
    FOREACH (Rel_AP IN capec.Related_Attack_Patterns.Related_Attack_Pattern |
      MERGE (pec:CAPEC { Name: "CAPEC-" + Rel_AP.CAPEC_ID })
      MERGE (cp)-[:RelatedAttackPattern {Nature: Rel_AP.Nature}]->(pec)
    )

    // Public References for CAPECs
    WITH cp, capec
    FOREACH (ExReference IN capec.References.Reference |
      MERGE (Ref:External_Reference_CAPEC {Reference_ID: ExReference.External_Reference_ID})
      MERGE (cp)-[rel:hasExternal_Reference {CAPEC_ID: cp.Name}]->(Ref)
    )
  ',
  {batchSize:1000, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;