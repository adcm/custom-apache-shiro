package com.aig.aigx;

import org.apache.shiro.aop.AnnotationResolver;
import org.apache.shiro.aop.MethodInvocation;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.aop.AuthorizingAnnotationMethodInterceptor;

/**
 *
 */
public class MyPermissionAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {
    /**
     * Default no-argument constructor that ensures this interceptor looks for
     * {@link org.apache.shiro.authz.annotation.RequiresPermissions RequiresPermissions} annotations in a method declaration.
     */
    public MyPermissionAnnotationMethodInterceptor() {
        super(new MyPermissionAnnotationHandler());
    }

    /**
     * @param resolver
     * @since 1.1
     */
    public MyPermissionAnnotationMethodInterceptor(AnnotationResolver resolver) {
        super(new MyPermissionAnnotationHandler(), resolver);
    }

    public void assertAuthorized(MethodInvocation mi) throws AuthorizationException {
        try {
            ((MyPermissionAnnotationHandler) getHandler()).assertAuthorized(getAnnotation(mi), mi.getArguments());
        } catch (AuthorizationException ae) {
            // Annotation handler doesn't know why it was called, so add the information here if possible.
            // Don't wrap the exception here since we don't want to mask the specific exception, such as
            // UnauthenticatedException etc.
            if (ae.getCause() == null)
                ae.initCause(new AuthorizationException("Not authorized to invoke method: " + mi.getMethod()));
            throw ae;
        }
    }
}
