package com.aig.aigx;

import org.apache.shiro.authz.aop.*;

import java.util.ArrayList;

/**
 *
 */
public class MyAnnotationsAuthorizingMethodInterceptor extends AnnotationsAuthorizingMethodInterceptor {

    public MyAnnotationsAuthorizingMethodInterceptor() {
        methodInterceptors = new ArrayList<AuthorizingAnnotationMethodInterceptor>(5);
        methodInterceptors.add(new RoleAnnotationMethodInterceptor());
        methodInterceptors.add(new MyPermissionAnnotationMethodInterceptor());
        methodInterceptors.add(new AuthenticatedAnnotationMethodInterceptor());
        methodInterceptors.add(new UserAnnotationMethodInterceptor());
        methodInterceptors.add(new GuestAnnotationMethodInterceptor());
    }
}
