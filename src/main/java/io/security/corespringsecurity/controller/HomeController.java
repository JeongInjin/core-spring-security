package io.security.corespringsecurity.controller;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class HomeController {

    @GetMapping(value = "/")
    public String home() throws Exception {
        return "home";
    }

    @PostMapping(value = "/")
    public String postHome() throws Exception {
        return "home";
    }

}
