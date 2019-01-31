package net.fredshaw.security.utils;

import java.io.IOException;
import java.io.Writer;
import java.util.Arrays;

import javax.annotation.processing.Filer;
import javax.lang.model.element.TypeElement;
import javax.tools.JavaFileObject;

import org.apache.commons.lang3.StringUtils;

import net.fredshaw.security.annotations.EnableOauthCheck;
import lombok.Data;

@Data
public class AnnotatedClass {
	
	private TypeElement annotatedElement;
	private String controller_pkg;
	private String base_pkg;
    private String client_id;
    private String client_secret;
    private String client_host;
    private String redirect_uri;
    private String req_code_url = "http://net.fredshaw/oauth/authorize";
    private String req_token_url = "http://net.fredshaw/oauth/token";
    
    public TypeElement getAnnotatedElement() {
    	return this.annotatedElement;
    }
    
    public AnnotatedClass(TypeElement classElement) {
    	
    	this.annotatedElement = classElement;
    	
    	EnableOauthCheck annotation = annotatedElement.getAnnotation(EnableOauthCheck.class);
    	
    	this.controller_pkg = annotation.controller_pkg();
    	this.client_id = annotation.client_id();
    	this.client_secret = annotation.client_secret();
    	this.client_host = annotation.client_host();
    	this.redirect_uri = "http://" + this.client_host + "/oauth/session/login";
    	
    	String appClassName = classElement.getQualifiedName().toString();
    	String[] class_segments = appClassName.split("\\.");
    	String[] pkg_segments =Arrays.copyOfRange(class_segments, 0, class_segments.length - 1);
    	this.base_pkg = StringUtils.join(pkg_segments, ".");
    }
    
    
    public void wirteFile(Filer filer) throws IOException {

    	this.writeAopClass(filer);
    	
    	this.writeControllerClass(filer);    	
    }
    
    
    
    private void writeAopClass(Filer filer) throws IOException {
        JavaFileObject jfo = filer.createSourceFile(base_pkg+".LoginChecker");
        Writer writer = jfo.openWriter();
        String file_str = 
        		"package " + base_pkg + ";\n" + 
        		"\n" + 
        		"import java.io.PrintWriter;\n" + 
        		"import java.net.MalformedURLException;\n" + 
        		"import java.net.URL;\n" + 
        		"import java.util.Collections;\n" + 
        		"import java.util.List;\n" + 
        		"import javax.servlet.http.HttpServletRequest;\n" + 
        		"import javax.servlet.http.HttpServletResponse;\n" + 
        		"import javax.servlet.http.HttpSession;\n" + 
        		"import org.aspectj.lang.ProceedingJoinPoint;\n" + 
        		"import org.aspectj.lang.annotation.Around;\n" + 
        		"import org.aspectj.lang.annotation.Aspect;\n" + 
        		"import org.aspectj.lang.annotation.Pointcut;\n" + 
        		"import org.springframework.stereotype.Component;\n" + 
        		"import org.springframework.web.context.request.RequestContextHolder;\n" + 
        		"import org.springframework.web.context.request.ServletRequestAttributes;\n" + 
        		"import com.alibaba.fastjson.JSON;\n" + 
        		"import com.alibaba.fastjson.JSONObject;\n" + 
        		"\n" + 
        		"\n" + 
        		"@Aspect\n" + 
        		"@Component\n" + 
        		"public class LoginChecker {\n" + 
        		"	private String client_id = \"" + client_id + "\";\n" + 
        		"	private String redirect_uri = \"" + redirect_uri + "\";\n" + 
        		"	private String req_url = \"" + req_code_url + "?response_type=code\" +\n" + 
        		"    		\"&client_id=\" + client_id + \"&redirect_uri=\" + redirect_uri;\n" + 
        		"	\n" + 
        		"	\n" + 
        		"	@Pointcut(\"execution(public * " + controller_pkg + "..*.*(..))\")\n" + 
        		"    public void check() {\n" + 
        		"    }\n" + 
        		"	\n" + 
        		"	\n" + 
        		"	@Around(\"check()\")\n" + 
        		"	public Object doAround(ProceedingJoinPoint pjp) throws Throwable {\n" + 
        		"		// 接收到请求，记录请求内容\n" + 
        		"        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();\n" + 
        		"        HttpServletRequest request = attributes.getRequest();\n" + 
        		"        HttpServletResponse response = attributes.getResponse();\n" + 
        		"        HttpSession session = request.getSession();\n" + 
        		"        		\n" + 
        		"        String path = request.getServletPath();\n" + 
        		"        // 已登录再次登录时，重定向到根目录\n" + 
        		"        if (session.getAttribute(\"_auth_user_id\") != null && path.equals(\"/oauth/session/login\")) {\n" + 
        		"    		response.sendRedirect(\"/\");\n" + 
        		"    		return null;\n" + 
        		"        }\n" + 
        		"        \n" + 
        		"        // 未登录时处理\n" + 
        		"        if (session.getAttribute(\"_auth_user_id\") == null && !path.equals(\"/oauth/session/login\")) {\n" + 
        		"        	session.setAttribute(\"stored_location\", path);\n" + 
        		"        	response.sendRedirect(req_url);\n" + 
        		"        	return null;\n" + 
        		"        }\n" + 
        		"        \n" + 
        		"        if (session.getAttribute(\"_auth_user_id\") != null && !is_accessible(request, session)) {\n" + 
        		"        	response.setCharacterEncoding(\"UTF-8\");  \n" + 
        		"            response.setContentType(\"text/html; charset=utf-8\");  \n" + 
        		"            PrintWriter out = response.getWriter();\n" + 
        		"            out.append(\"您没有权限\");\n" + 
        		"        	return null;\n" + 
        		"        }\n" + 
        		"        return pjp.proceed();\n" + 
        		"	}\n" + 
        		"	\n" + 
        		"	private boolean is_accessible(HttpServletRequest req, HttpSession session) {		\n" + 
        		"		String req_path = req.getServletPath();\n" + 
        		"		List<String> req_param_keys = Collections.list(req.getParameterNames());\n" + 
        		"		\n" + 
        		"		JSONObject json = JSON.parseObject(session.getAttribute(\"_auth_user_id\").toString());\n" + 
        		"		List<String> urls = json.getJSONArray(\"authorities\").toJavaList(String.class);\n" + 
        		"		\n" + 
        		"		for (String u : urls) {\n" + 
        		"			try {\n" + 
        		"				URL url = new URL(u);\n" + 
        		"				String path = url.getPath();\n" + 
        		"				String query = url.getQuery();\n" + 
        		"						\n" + 
        		"				if (req_path.equals(path)) {\n" + 
        		"					for(String param_key : req_param_keys ) {\n" + 
        		"						String param_segment = param_key + \"=\" + req.getParameter(param_key);\n" + 
        		"						if (!query.matches(param_segment+\"&|$\"))\n" + 
        		"							continue;\n" + 
        		"					}\n" + 
        		"					return true;\n" + 
        		"				}\n" + 
        		"			} catch (MalformedURLException e) {\n" + 
        		"				continue;\n" + 
        		"			}\n" + 
        		"		}\n" + 
        		"		return false;\n" + 
        		"	}\n" + 
        		"}\n" + 
        		"";
        writer.write(file_str);
        writer.close();
    }
    
    
    private void writeControllerClass(Filer filer) throws IOException {
    	JavaFileObject jfo = filer.createSourceFile(controller_pkg+".AuthSessionController");
        Writer writer = jfo.openWriter();
    	writer.write(
    			"package " + controller_pkg + ";\n" + 
    			"\n" + 
    			"import java.io.IOException;\n" + 
    			"\n" + 
    			"import javax.servlet.http.HttpServletRequest;\n" + 
    			"import javax.servlet.http.HttpServletResponse;\n" + 
    			"import javax.servlet.http.HttpSession;\n" + 
    			"\n" + 
    			"import org.springframework.util.StringUtils;\n" + 
    			"import org.springframework.web.bind.annotation.RequestMapping;\n" + 
    			"import org.springframework.web.bind.annotation.RequestMethod;\n" + 
    			"import org.springframework.web.bind.annotation.RestController;\n" + 
    			"\n" + 
    			"import com.alibaba.fastjson.JSON;\n" + 
    			"import com.alibaba.fastjson.JSONObject;\n" + 
    			"\n" + 
    			"import okhttp3.FormBody;\n" + 
    			"import okhttp3.OkHttpClient;\n" + 
    			"import okhttp3.Request;\n" + 
    			"import okhttp3.Response;\n" + 
    			"\n" + 
    			"@RestController\n" + 
    			"@RequestMapping(\"/oauth/session\")\n" + 
    			"public class AuthSessionController {\n" + 
    			"	\n" + 
    			"	private String client_id = \""+ client_id + "\";\n" + 
    			"	private String client_secret = \"" + client_secret + "\";\n" + 
    			"	private String redirect_uri = \"" + redirect_uri + "\";\n" + 
    			"	private String get_token_uri = \"" + req_token_url + "\";\n" + 
    			"	\n" + 
    			"	\n" + 
    			"	@RequestMapping(value = \"login\", method = RequestMethod.GET)\n" + 
    			"	public void doLogin(HttpServletRequest req, HttpServletResponse res) throws IOException {\n" + 
    			"		\n" + 
    			"		HttpSession session = req.getSession();\n" + 
    			"		String code = req.getParameter(\"code\");\n" +
    			"		\n" + 
    			"		if (StringUtils.isEmpty(code)) {\n" + 
    			"			res.sendRedirect(\"/\");\n" + 
    			"			return;\n" + 
    			"		}\n" + 
    			"		\n" + 
    			"		JSONObject token = this.getToken(code);\n" +
    			"		if (!StringUtils.isEmpty(token.getString(\"access_token\"))) {\n" + 
    			"			session.setAttribute(\"_auth_user_id\", token.toJSONString());\n" + 
    			"			\n" + 
    			"			String stored_location = (String) session.getAttribute(\"stored_location\");\n" + 
    			"			session.removeAttribute(\"stored_location\");\n" + 
    			"			if (stored_location != null)\n" + 
    			"				res.sendRedirect(stored_location);\n" + 
    			"		}	\n" + 
    			"	}\n" + 
    			"	\n" + 
    			"	\n" + 
    			"	private JSONObject getToken(String code) throws IOException {\n" + 
    			"		OkHttpClient client = new OkHttpClient.Builder().build();\n" + 
    			"		FormBody formBody = new FormBody\n" + 
    			"                .Builder()\n" + 
    			"                .add(\"client_id\", client_id)\n" + 
    			"                .add(\"client_secret\", client_secret)\n" + 
    			"                .add(\"grant_type\", \"authorization_code\")\n" + 
    			"                .add(\"code\", code)\n" + 
    			"                .add(\"redirect_uri\", redirect_uri)\n" + 
    			"                .build();\n" + 
    			"		Request request = new Request.Builder()\n" + 
    			"				.post(formBody)\n" + 
    			"				.url(get_token_uri)\n" + 
    			"				.build();\n" + 
    			"		Response response = client.newCall(request).execute();\n" + 
    			"		JSONObject authInfo = JSON.parseObject(response.body().string());\n" + 
    			"		return authInfo;\n" + 
    			"	}\n" + 
    			"	\n" + 
    			"	\n" + 
    			"	@RequestMapping(value = \"logout\", method = RequestMethod.GET)\n" + 
    			"	public void doLogout(HttpServletRequest req, HttpServletResponse res) throws IOException {\n" + 
    			"		HttpSession session = req.getSession();\n" + 
    			"		session.removeAttribute(\"_auth_user_id\");\n" + 
    			"		res.sendRedirect(\"/\");\n" + 
    			"	}\n" + 
    			"	\n" + 
    			"\n" + 
    			"}\n" + 
    			"");
    	writer.close();
    }
    
    
    
    
}
