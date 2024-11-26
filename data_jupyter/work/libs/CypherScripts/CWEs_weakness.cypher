// ------------------------------------------------------------------------
// Insert Weaknesses for CWEs
UNWIND [cweWeaknessFilesToImport] AS files
CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS weakness RETURN weakness',
  '
    // Insert CWEs
    MERGE (w:CWE {
      Name: "CWE-" + weakness.ID
    })
    SET w.Extended_Name = weakness.Name,
      w.Abstraction = weakness.Abstraction,
      w.Structure = weakness.Structure,
      w.Status = weakness.Status,
      w.Description = weakness.Description,
      w.Extended_Description = weakness.Extended_Description,
      w.Likelihood_Of_Exploit = weakness.Likelihood_Of_Exploit,
      w.Background_Details = weakness.Background_Details.Background_Detail,
      w.Modes_Of_Introduction = [value IN weakness.Modes_Of_Introduction.Introduction | value.Phase],
      w.Submission_Date = weakness.Content_History.Submission.Submission_Date,
      w.Submission_Name = weakness.Content_History.Submission.Submission_Name,
      w.Submission_Organization = weakness.Content_History.Submission.Submission_Organization,
      w.Modification_Name = [value in weakness.Content_History.Modification WHERE value.Modification_Name IS NOT NULL | toString(value.Modification_Name)],
      w.Modification_Organization = [value in weakness.Content_History.Modification WHERE value.Modification_Organization IS NOT NULL | toString(value.Modification_Organization)],
      w.Modification_Date = [value in weakness.Content_History.Modification WHERE value.Modification_Date IS NOT NULL | toString(value.Modification_Date)],
      w.Modification_Comment= [value in weakness.Content_History.Modification WHERE value.Modification_Comment IS NOT NULL | toString(value.Modification_Comment)],
      w.Alternate_Term_Term= CASE apoc.meta.cypher.type (weakness.Alternate_Terms.Alternate_Term)
        WHEN "MAP" THEN toStringList(apoc.convert.toList(weakness.Alternate_Terms.Alternate_Term.Term))
        WHEN "LIST OF MAP" THEN [value in weakness.Alternate_Terms.Alternate_Term | value.Term]
        ELSE null
        END,
      w.Alternate_Term_Description = CASE apoc.meta.cypher.type(weakness.Alternate_Terms.Alternate_Term)
        WHEN "MAP" THEN toStringOrNull(weakness.Alternate_Terms.Alternate_Term.Description)
        WHEN "LIST OF MAP" THEN [value in weakness.Alternate_Terms.Alternate_Term WHERE value.Description IS NOT NULL | value.Description]
        ELSE null
        END,
      w.Note_Type = CASE apoc.meta.cypher.type (weakness.Notes.Note)
        WHEN "MAP" THEN toStringList(apoc.convert.toList(weakness.Notes.Note.Type))
        WHEN "LIST OF MAP" THEN [value in weakness.Notes.Note | value.Type]
        ELSE null
        END,
      w.Note_Text = CASE apoc.meta.cypher.type (weakness.Notes.Note)
        WHEN "MAP" THEN CASE 
              WHEN apoc.map.get(weakness.Notes.Note,"text","def") = "def" THEN 
                  CASE WHEN apoc.map.get(weakness.Notes.Note,"xhtml:p") IS NOT NULL THEN toStringList(apoc.convert.toList(weakness.Notes.Note.xhtml:p)) 
                        ELSE null END
              ELSE toStringList(apoc.convert.toList(weakness.Notes.Note.text)) END
        WHEN "LIST OF MAP" THEN apoc.coll.unionAll([value in weakness.Notes.Note WHERE value.text IS NOT NULL | value.text], apoc.coll.flatten([value in weakness.Notes.Note WHERE value.xhtml:p IS NOT NULL | value.xhtml:p]))
        ELSE null END,
      w.Affected_Resources = [value IN weakness.Affected_Resources.Affected_Resource | value],
      w.Functional_Areas = [value IN weakness.Functional_Areas.Functional_Area | value]

    // Insert Related Weaknesses CWE --> CWE
    WITH w, weakness
    FOREACH (Rel_Weakness IN weakness.Related_Weaknesses.Related_Weakness |
      MERGE (cwe:CWE {Name: "CWE-" + Rel_Weakness.CWE_ID})
      MERGE (w)-[:Related_Weakness {Nature: Rel_Weakness.Nature}]->(cwe)
    )

    // Insert Applicable Platforms for CWEs
    WITH w, weakness
    FOREACH (lg IN weakness.Applicable_Platforms.Language |
      MERGE (ap:Applicable_Platform {Type: "Language", Prevalence: lg.Prevalence,
                                    Name: coalesce(lg.Name, " NOT SET "), Class: coalesce(lg.Class, " NOT SET ")})
      MERGE (w)-[:Applicable_Platform]->(ap)
    )

    WITH w, weakness
    FOREACH (tch IN weakness.Applicable_Platforms.Technology |
      MERGE (ap:Applicable_Platform {Type: "Technology", Prevalence: tch.Prevalence,
                                    Name: coalesce(tch.Name, " NOT SET "), Class: coalesce(tch.Class, " NOT SET ")})
      MERGE (w)-[:Applicable_Platform]->(ap)
    )
    
    WITH w, weakness
    FOREACH (arc IN weakness.Applicable_Platforms.Architecture |
      MERGE (ap:Applicable_Platform {Type: "Architecture", Prevalence: arc.Prevalence,
                                    Name: coalesce(arc.Name, " NOT SET "), Class: coalesce(arc.Class, " NOT SET ")})
      MERGE (w)-[:Applicable_Platform]->(ap)
    )

    WITH w, weakness
    FOREACH (os IN weakness.Applicable_Platforms.Operating_System |
      MERGE (ap:Applicable_Platform {Type: "Operating System", Prevalence: os.Prevalence,
                                    Name: coalesce(os.Name, " NOT SET "), Class: coalesce(os.Class, " NOT SET ")})
      MERGE (w)-[:Applicable_Platform]->(ap)
    )

    // Insert Demonstrative Examples for CWEs
    WITH w, weakness
    FOREACH (example IN weakness.Demonstrative_Examples.Demonstrative_Example |
      MERGE (ex:Demonstrative_Example {
        Intro_Text: toString(example.Intro_Text)
      })
      MERGE (w)-[r:hasExample]->(ex)
      SET r.Body_Text = toString(example.Body_Text),
      r.Example_Code = [value IN example.Example_Code | toString(value)]
    )

    // Insert Consequences for CWEs
    WITH w, weakness
    FOREACH (consequence IN weakness.Common_Consequences.Consequence |
      MERGE (con:Consequence {Scope: [value IN consequence.Scope | value]})
      MERGE (w)-[rel:hasConsequence]->(con)
      SET rel.Impact = [value IN consequence.Impact | value],
      rel.Note = toStringOrNull(consequence.Note), rel.Likelihood = [value IN consequence.Likelihood | value],
  rel.Scope = [value in consequence.Scope | value]
    )

    // Insert Detection Methods for CWEs
    WITH w, weakness
    FOREACH (dec IN weakness.Detection_Methods.Detection_Method |
      MERGE (d:Detection_Method {
        Method: dec.Method
      })
      MERGE (w)-[wd:canBeDetected {Description:toString(dec.Description)}]->(d)
      SET wd.Effectiveness = dec.Effectiveness, wd.Effectiveness_Notes = dec.Effectiveness_Notes,
      wd.Detection_Method_ID = dec.Detection_Method_ID
    )

    // Insert Potential Mitigations for CWEs
    WITH w, weakness
    FOREACH (mit IN weakness.Potential_Mitigations.Mitigation |
      MERGE (m:Mitigation {Description: toString(mit.Description)})
      SET m.Phase = [value IN mit.Phase | value],
        m.Strategy = mit.Strategy,
        m.Effectiveness = mit.Effectiveness, m.Effectiveness_Notes = mit.Effectiveness_Notes,
      m.Mitigation_ID = mit.Mitigation_ID
      MERGE (w)-[:hasMitigation]->(m)
    )

    // Insert Related Attack Patterns - CAPEC for CWEs
    WITH w, weakness
    FOREACH (rap IN weakness.Related_Attack_Patterns.Related_Attack_Pattern |
      MERGE (cp:CAPEC {
        Name: "CAPEC-" + rap.CAPEC_ID
      })
      MERGE (w)-[:RelatedAttackPattern]->(cp)
    )

    // Public References for CWEs
    WITH w, weakness
    FOREACH (exReference IN weakness.References.Reference |
      MERGE (ref:External_Reference_CWE {Reference_ID: exReference.External_Reference_ID})
      MERGE (w)-[:hasExternal_Reference]->(ref)
    )
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;