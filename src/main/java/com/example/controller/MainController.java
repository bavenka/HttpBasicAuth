package com.example.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Created by Pavel on 21.12.2016.
 */
@Controller
public class MainController {
    @RequestMapping("/")
    public String getMainPage(){
        return "/index.html";
    }
}
