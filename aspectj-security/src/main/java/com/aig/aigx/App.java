package com.aig.aigx;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */
public class App {
    private static final transient Logger log = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) {
        Factory<org.apache.shiro.mgt.SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        Subject currentUser = SecurityUtils.getSubject();
        Session session = currentUser.getSession();

        session.setAttribute("someKey", "aValue");
        String value = (String) session.getAttribute("someKey");
        if (value.equals("aValue")) {
            log.info("Retrieved the correct value! [" + value + "]");
        }

        // let's login the current user so we can check against roles and permissions:
        if (!currentUser.isAuthenticated()) {
            UsernamePasswordToken token = new UsernamePasswordToken("user", "user");
            token.setRememberMe(true);
            try {
                currentUser.login(token);
            } catch (UnknownAccountException uae) {
                log.info("There is no user with username of " + token.getPrincipal());
            } catch (IncorrectCredentialsException ice) {
                log.info("Password for account " + token.getPrincipal() + " was incorrect!");
            } catch (LockedAccountException lae) {
                log.info("The account for username " + token.getPrincipal() + " is locked.  " +
                        "Please contact your administrator to unlock it.");
            }
            // ... catch more exceptions here (maybe custom ones specific to your application?
            catch (AuthenticationException ae) {
                //unexpected condition?  error?
            }
        }

        new App().test(1l);
        new App().test1(1l, "access");
        new App().test2(1l, 2l, "access");
        new App().test3("access", 1l, 3l);
        new App().test2(1l, 3l, "access");

    }

    @RequiresPermissions("sp:access:{0}")
    private void test(Long a) {
        log.info("has permissions to access sp " + a);
    }

    @RequiresPermissions("sp:{1}:{0}")
    private void test1(Long a, String permission) {
        log.info("has permissions to " + permission + " sp " + a);
    }

    @RequiresPermissions(value = {"sp:{2}:{0}", "sp:{2}:{1}"}, logical = Logical.AND)
    private void test2(Long a, Long b, String permission) {
        log.info("has permissions to " + permission + " sp " + a + " and " + b);
    }

    @RequiresPermissions(value = {"sp:{0}:{1}", "sp:{0}:{2}"}, logical = Logical.OR)
    private void test3(String permission, Long a, Long b) {
        log.info("has permissions to " + permission + " sp " + a + " or " + b);
    }
}
