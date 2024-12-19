package com.metaconvo.Metaconvo.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class HomeController {

//    @Autowired
//    OAuth2AuthorizedClientService oAuth2AuthorizedClientService;
//
//    @Autowired
//    Oauth2Token oauth2Token;


    @GetMapping("/")
    public String helloProtected(HttpServletRequest httpServletRequest) throws JsonProcessingException {
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        Object principal = auth.getPrincipal();
//
//        System.out.println(oauth2Token.getAccessToken());
            return "Protected Accessed !!\n Hello " ;

    }

//    @GetMapping("/currentUser")
//    public Object currentUser() {
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        Object principal = auth.getPrincipal();
//        return principal;
//
//    }
}
