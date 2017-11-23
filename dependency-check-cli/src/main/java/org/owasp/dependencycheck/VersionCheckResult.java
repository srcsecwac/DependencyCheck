package org.owasp.dependencycheck;

import org.owasp.dependencycheck.VersionCheckRuler.VersionRange;
import org.owasp.dependencycheck.dependency.Dependency;

public class VersionCheckResult {
	String name;
	String version;	
	String validVersion;
	public VersionCheckResult(String range, Dependency dep){
		name = dep.getFileName();
		validVersion = range;
	}
	public void SetVersion(String ver){
		version = ver;
	}
}
