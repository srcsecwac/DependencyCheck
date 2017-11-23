package org.owasp.dependencycheck;



import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;

public class VersionCheckRuler {
	class InvalidVersion extends Exception{		
		private static final long serialVersionUID = 11112424341L;		
	}
	class VersionRange{
		public String ge;
		public String le;
		public String g;
		public String l;
		public boolean inRange(String range) throws InvalidVersion{			
			range = range.trim();
			if ("".equals(range) || validversion(range)){
				throw new InvalidVersion();
			}
			if (null !=ge &&(!"".equals(ge))){
				if (!IsLess(ge,range,true)){
					return false;
				}
			}
			if (null !=g &&(!"".equals(g))){
				if (!IsLess(g,range,false)){
					return false;
				}
			}
			if (null !=le &&(!"".equals(le))){
				if (!IsLess(range,le,true)){
					return false;
				}
			}
			if (null !=l &&(!"".equals(l))){
				if (!IsLess(range,l,false)){
					return false;
				}
			}
			
			return true;
		}
		public boolean IsValid(){
			/* ����ȫΪ�� */
			if (null == ge && null == le&& null == g && null==l){
				return false;
			}
			/* ����ȫΪ�� */
			if ("".equals(ge)&& "".equals(le)&&"".equals(g)&&"".equals(l)){
				return false;
			}
			/* ge��g ֻ�ܴ���һ�� */
			if (null !=ge && null != g && (!"".equals(ge)) && (!"".equals(g))){
				return false;
			}
			/* le��l ֻ�ܴ���һ�� */
			if (null !=le && null != l&&(!"".equals(le)) && (!"".equals(l))){
				return false;
			}			
			
			return validversion(g) && validversion(ge) && validversion(l) && validversion(le);
		}
		
		public boolean validversion(String version){
			/* �հ汾��ϢΪ�Ϸ�*/
			if (null ==version){
				return true;
			}
			/* �հ汾��ϢΪ�Ϸ�*/
			if ("".equals(version)){
				return true;
			}
			try{
				String[]  subv = version.split(".");
				for(int i = 0;i<subv.length;i++){
					 Integer.parseInt( subv[i]);				
				}
			}catch(Exception ex){
				return false;
			}
			return true;
		}
		/* < �Ƿ����, true== lessequal ʱ����<= �Ƿ����*/
		private boolean IsLess(String v1,String v2,boolean lessequal) throws NumberFormatException{
			String[]  sub1 = v1.split(".");
			String[] sub2 = v2.split(".");
			int len1 = sub1.length;
			int len2 = sub2.length;
			
			for(int i = 0;i<len1&&i<len2;i++){
				int sv1 =  Integer.parseInt( sub1[i]);
				int sv2 =  Integer.parseInt( sub1[i]); 
				if (sv1>sv2){
					return false;
				}
				if (sv1 < sv2){
					return true;
				}
			}
			if (len2 >len1 ) {
				return false;
			}
			if (!lessequal){
				if (len2 == len1){
					return false;
				}
			}
			return true;
		}
		
	}
	public String FileNameKey;
	public VersionRange[] ValidVersion;
	
	public String CheckInvalideDeps(Dependency dep){
		if (dep.getFileName().contains(FileNameKey)){
			for(VersionRange vr: ValidVersion){
				if (vr.IsValid()){
					for (Evidence evi:dep.getVersions()){
						try{
							if (!vr.inRange(evi.getValue())){
								return evi.getValue();
							}
						}catch(InvalidVersion ex){
							continue;
						}
						
					}
				}
			}
		}
		return null;
		
	}
	public String getRangeDes(){
		StringBuilder sb = new StringBuilder();
		for (VersionRange vr:ValidVersion){
			sb.append(" ");
			if (null != vr.ge &&( !"".equals(vr.ge))){
				sb.append(" version >= ");
				sb.append(vr.ge);
			}
			if (null != vr.g &&( !"".equals(vr.g))){
				sb.append(" version > ");
				sb.append(vr.g);
			}
			if (null != vr.le &&( !"".equals(vr.le))){
				sb.append(" version <= ");
				sb.append(vr.le);
			}
			if (null != vr.l &&( !"".equals(vr.l))){
				sb.append(" version < ");
				sb.append(vr.l);
			}
			sb.append(" ");
		}
		return sb.toString();
	}

}
