package org.owasp.dependencycheck;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.List;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.core.JsonProcessingException;

import org.owasp.dependencycheck.VersionCheckRuler.VersionRange;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VersionChecker {
    private static final long serialVersionUID = 111243L;
    
    private static final Logger LOGGER = LoggerFactory.getLogger(VersionChecker.class);
	
	VersionChecker(){
		
		
	}
	
	VersionCheckRuler[] VersionRules;
	
	
	VersionCheckResult CheckRange(Dependency dep){
		String invalidVer = null;
		for(VersionCheckRuler rule:VersionRules){
			if (null != (invalidVer=rule.CheckInvalideDeps(dep))){
				
				VersionCheckResult vcr = new VersionCheckResult(rule.getRangeDes(),dep);
				vcr.SetVersion(invalidVer);
				return vcr;
			}
		}
		return null;
	}
	public static VersionChecker getChecker(String confName){
		ObjectMapper mapper = new ObjectMapper();  
		try{
			InputStream in = FileUtils.getResourceAsStream(confName);
			//InputStreamReader in = new FileReader(confPath);
			VersionChecker checker = mapper.readValue(in, VersionChecker.class);
			return checker;
	        
        }catch(Exception ex){
        	LOGGER.error(ex.toString());
        }
		return null;
	}
	public static void GeneReport(String reportPath,List<VersionCheckResult> results){
		ObjectMapper mapper = new ObjectMapper();  
		try{
			//StreamWriter out = new FileReader(reportPath);
			OutputStreamWriter out = new FileWriter(reportPath);
			String resstr = mapper.writeValueAsString(results);
			out.write(resstr);
			out.flush();	
	        
        }catch(Exception ex){
        	LOGGER.error(ex.toString());
        }
	}
}
