package com.example.vaccination.controller;

import com.example.vaccination.model.entity.InjectionResult;
import com.example.vaccination.model.entity.VaccineType;
import com.example.vaccination.service.InjectionResultService;
import com.example.vaccination.service.VaccineTypeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
public class ReportInjectionResultChartController {

    @Autowired
    private InjectionResultService injectionResultService;

    @Autowired
    private VaccineTypeService vaccineTypeService;

    @GetMapping("/reportInjectionResultChart")
    public String getChartData(Model model,
                               @RequestParam(name = "yearSelection", required = false) String yearSelect) {
        if(yearSelect == "0"){
            return "redirect:/reportInjectionResultChart";
        }
        List<String> injectionResultList = injectionResultService.count(yearSelect);
        model.addAttribute("yearSelection", yearSelect);
        model.addAttribute("injectionResultList",injectionResultList);

        return "reportInjectionResultChart";
    }
}
