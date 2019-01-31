package net.fredshaw.security.processors;


import java.io.IOException;
import java.util.Set;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.Filer;
import javax.annotation.processing.Messager;
import javax.annotation.processing.ProcessingEnvironment;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.util.Elements;
import javax.lang.model.util.Types;
import javax.tools.Diagnostic;

import net.fredshaw.security.annotations.EnableOauthCheck;
import net.fredshaw.security.utils.AnnotatedClass;




@SuppressWarnings("restriction")
@SupportedAnnotationTypes("net.fredshaw.security.annotations.EnableOauthCheck")
public class EnableOauthCheckProcessor extends AbstractProcessor {
    
    private Types typeUtils;
    private Elements elementUtils;
    private Filer filer;
    private Messager messager;
    
    
    @Override
    public synchronized void init(ProcessingEnvironment processingEnv) {
        super.init(processingEnv);
        typeUtils = processingEnv.getTypeUtils();
        elementUtils = processingEnv.getElementUtils();
        filer = processingEnv.getFiler();
        messager = processingEnv.getMessager();
    }
    
    
    @Override
    public SourceVersion getSupportedSourceVersion() {
        return SourceVersion.latestSupported();
    }

    
    
    
    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
        
        
        for (Element elem : roundEnv.getElementsAnnotatedWith(EnableOauthCheck.class)) {
        	// 被注册元素不是类的不处理
        	if (elem.getKind() != ElementKind.CLASS) {
        		error(elem, "Only classes can be annotated with @%s",EnableOauthCheck.class.getSimpleName());
        		return true; // 退出处理
        	}
        	
        	
        	AnnotatedClass ac = new AnnotatedClass((TypeElement) elem);
        	if (!isValidClass(ac))
        		return true;
            
        	
        	try {
				ac.wirteFile(filer);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				error(elem, "Write Class:@%s Error", elem.getSimpleName());
				return true;
			}
        	
        }
        return true;
    }
    
    
    
    
    private void error(Element e, String msg, Object... args) {  
	    messager.printMessage(Diagnostic.Kind.ERROR, String.format(msg, args), e);
    }
    
    
    private boolean isValidClass(AnnotatedClass item) {
    	
    	TypeElement classElement = item.getAnnotatedElement();
    	 
        if (!classElement.getModifiers().contains(Modifier.PUBLIC)) {
          error(classElement, "The class %s is not public.",
              classElement.getQualifiedName().toString());
          return false;
        }
     
        // 检查是否是一个抽象类
        if (classElement.getModifiers().contains(Modifier.ABSTRACT)) {
          error(classElement, "The class %s is abstract. You can't annotate abstract classes with @%",
              classElement.getQualifiedName().toString(), EnableOauthCheck.class.getSimpleName());
          return false;
        }
        
        
     
    	return true;
    }

    
    
    
    

    
    
    

    
}
