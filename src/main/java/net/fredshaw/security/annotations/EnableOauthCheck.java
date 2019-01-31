package net.fredshaw.security.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface EnableOauthCheck {
	String controller_pkg();
    String client_id();
    String client_secret();
    String client_host();
}
