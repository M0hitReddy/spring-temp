package com.metaconvo.Metaconvo.controller;


import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/")
@CrossOrigin(origins = "http://localhost:5173")
public class CurrentUserController {

//    @CrossOrigin(origins = "http://localhost:3000",allowCredentials = "true", originPatterns = "http://localhost:3000",allowedHeaders = "*")
    @GetMapping("/mee")
    public Object currentUser() {
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        Object principal = auth.getDetails();
        return "auth";

    }
}
