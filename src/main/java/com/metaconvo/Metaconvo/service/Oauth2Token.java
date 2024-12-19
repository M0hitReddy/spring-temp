//package com.metaconvo.Metaconvo.service;
//
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.oauth2.core.oidc.user.OidcUser;
//import org.springframework.security.oauth2.jwt.Jwt;
//
////@Service
//public class Oauth2Token {
//    public String getAccessToken() {
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        Object principal = auth.getPrincipal();
//
//        if (principal instanceof OidcUser) {
//            OidcUser oidcUser = (OidcUser) principal;
////            System.out.println(oidcUser.getIdToken().getTokenValue());
////            return "Protected Accessed !!\n Hello " + oidcUser.getFullName();
//            return oidcUser.getIdToken().getTokenValue();
//        } else if (principal instanceof Jwt) {
//            Jwt jwt = (Jwt) principal;
////            System.out.println(jwt.getTokenValue());
////            return "Protected Accessed !!\n Hello " + jwt.getSubject();
//            return jwt.getTokenValue();
//        } else {
//            return null;
//        }
//    }
//}