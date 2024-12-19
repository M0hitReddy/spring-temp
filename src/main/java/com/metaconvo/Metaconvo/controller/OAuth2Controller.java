package com.metaconvo.Metaconvo.controller;


import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class OAuth2Controller {

    // Handle successful login
    @GetMapping("/login/oauth2/code/google")
    public String handleGoogleLogin(Authentication authentication, RedirectAttributes redirectAttributes) {
        // Get the authenticated user's details
        OAuth2User principal = (OAuth2User) authentication.getPrincipal();
        String username = principal.getAttribute("name");
        String email = principal.getAttribute("email");

        // Optionally, store user data in the session or database
        redirectAttributes.addAttribute("user", username);
        redirectAttributes.addAttribute("email", email);

        // Redirect to the frontend with user info
        return "redirect:/me";  // Or any page you want to redirect after login
    }

    // Display the dashboard with user info
    @GetMapping("/me")
    public String dashboard(@RequestParam String user, @RequestParam String email) {
        // Display the user information on the dashboard page
        return "dashboard";  // Render a view (Thymeleaf or another template engine)
    }
}
