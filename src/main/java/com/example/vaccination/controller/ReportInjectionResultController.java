package com.example.vaccination.controller;

import com.example.vaccination.model.entity.Customer;
import com.example.vaccination.model.entity.InjectionResult;
import com.example.vaccination.model.entity.VaccineType;
import com.example.vaccination.service.InjectionResultService;
import com.example.vaccination.service.VaccineTypeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import java.util.Date;
import java.util.List;

@Controller
public class ReportInjectionResultController {
    @Autowired
    private InjectionResultService injectionResultService;

    @Autowired
    private VaccineTypeService vaccineTypeService;

    @GetMapping( "/reportInjectionResult")
    public String findAll(Model model){
        List<InjectionResult> injectionResultList = injectionResultService.findAll();
        List<VaccineType> vaccineTypeList = vaccineTypeService.findAll();
        model.addAttribute("vaccineTypeList",vaccineTypeList);
        model.addAttribute("injectionResultList", injectionResultList);
        return "reportInjectionResult";
    }

    @GetMapping("/searchResult")
    public String searchResults(Model model, RedirectAttributes red,
                                @RequestParam(value = "startDate", required = false) @DateTimeFormat(pattern = "yyyy-MM-dd") Date startDate,
                                @RequestParam(value = "endDate", required = false) @DateTimeFormat(pattern = "yyyy-MM-dd") Date endDate,
                                @RequestParam(value = "vaccineTypeName", required = false) String vaccineTypeName,
                                @RequestParam(value = "prevention", required = false) String prevention) {

        List<VaccineType> vaccineTypeList = vaccineTypeService.findAll();
        List<InjectionResult> injectionResultList = null;
        if (startDate != null || endDate != null || vaccineTypeName != null || prevention != null) {
            injectionResultList = injectionResultService.searchResults(startDate, endDate, vaccineTypeName, prevention);
            model.addAttribute("injectionResultList", injectionResultList);
            model.addAttribute("vaccineTypeList", vaccineTypeList);
            model.addAttribute("startDate", startDate);
            model.addAttribute("endDate", endDate);
            model.addAttribute("vaccineTypeName", vaccineTypeName);
            model.addAttribute("prevention", prevention);
            return "reportInjectionResult";
        }
//        ///---Find by all---------------------------------------------------------------------------------
//        if(startDate != null && endDate != null && prevention != "" && vaccineTypeName != ""){
//            ///--Check date
//            if (endDate.before(startDate)) {
//                List<InjectionResult> injectionResultList = injectionResultService.findResultsByInjectionDateAndVaccineTypeName(startDate, endDate, vaccineTypeName);
//                model.addAttribute("injectionResultList", injectionResultList);
//                model.addAttribute("vaccineTypeList", vaccineTypeList);
//                model.addAttribute("startDate", startDate);
//                model.addAttribute("endDate", endDate);
//                model.addAttribute("error", "To date less than From date");
//                red.addFlashAttribute("error", "To date less than From date");
//                return "reportInjectionResult";
//            }else {
//                List<InjectionResult> injectionResultList = injectionResultService.searchResults(startDate, endDate, vaccineTypeName, prevention);
//                model.addAttribute("injectionResultList", injectionResultList);
//                model.addAttribute("vaccineTypeList", vaccineTypeList);
//                model.addAttribute("startDate", startDate);
//                model.addAttribute("endDate", endDate);
//                model.addAttribute("vaccineTypeName", vaccineTypeName);
//                model.addAttribute("prevention", prevention);
//                return "reportInjectionResult";
//            }
//        } else {
//            ///---Tìm kiếm bằng startDate và endDate-------------------------------------------------------
//            if (startDate != null && endDate != null && prevention == "" && vaccineTypeName == "") {
//                ///--Check date
//                if (endDate.before(startDate)) {
//                    List<InjectionResult> injectionResultList = injectionResultService.findResultsByInjectionDateAndVaccineTypeName(startDate, endDate, vaccineTypeName);
//                    model.addAttribute("injectionResultList", injectionResultList);
//                    model.addAttribute("vaccineTypeList", vaccineTypeList);
//                    model.addAttribute("startDate", startDate);
//                    model.addAttribute("endDate", endDate);
//                    model.addAttribute("error", "To date less than From date");
//                    red.addFlashAttribute("error", "To date less than From date");
//                    return "reportInjectionResult";
//                }else {
//                    List<InjectionResult> injectionResultList = injectionResultService.findResultsByInjectionDate(startDate, endDate);
//                    model.addAttribute("injectionResultList", injectionResultList);
//                    model.addAttribute("vaccineTypeList", vaccineTypeList);
//                    model.addAttribute("startDate", startDate);
//                    model.addAttribute("endDate", endDate);
//                    return "reportInjectionResult";
//                }
//            }
//            ///---Find by From date------------------------------------------------------------------------
//            else if (startDate != null && endDate == null && vaccineTypeName =="" && prevention == "") {
//                List<InjectionResult> injectionResultList = injectionResultService.findResultsByStartDate(startDate);
//                model.addAttribute("injectionResultList", injectionResultList);
//                model.addAttribute("vaccineTypeList", vaccineTypeList);
//                model.addAttribute("startDate", startDate);
//                return "reportInjectionResult";
//            }
//            ///---Find by end date-------------------------------------------------------------------------
//            else if (startDate == null && endDate != null && vaccineTypeName =="" && prevention == "") {
//                    List<InjectionResult> injectionResultList = injectionResultService.findResultsByEndDate(endDate);
//                    model.addAttribute("injectionResultList", injectionResultList);
//                    model.addAttribute("vaccineTypeList", vaccineTypeList);
//                    model.addAttribute("endDate", endDate);
//                    return "reportInjectionResult";
//            }
//            ///---Find by Vaccine Type---------------------------------------------------------------------
//            else if (startDate == null && endDate == null && prevention == "") {
//                List<InjectionResult> injectionResultList = injectionResultService.findResultsByVaccineTypeName(vaccineTypeName);
//                model.addAttribute("injectionResultList", injectionResultList);
//                model.addAttribute("vaccineTypeList", vaccineTypeList);
//                model.addAttribute("vaccineTypeName", vaccineTypeName);
//                return "reportInjectionResult";
//            }
//            ///---find by prevention ------------------------------------------------------------------------
//            else if (startDate == null && endDate == null && vaccineTypeName == "") {
//                List<InjectionResult> injectionResultList = injectionResultService.findResultsByPrevention(prevention);
//                model.addAttribute("injectionResultList", injectionResultList);
//                model.addAttribute("vaccineTypeList", vaccineTypeList);
//                model.addAttribute("prevention", prevention);
//                return "reportInjectionResult";
//            }
//            ///---From and privention-----------------------------------------------------
//            else if (startDate != null && endDate == null && prevention != "" ) {
//                List<InjectionResult> injectionResultList = injectionResultService.findResultsByStartDateAndPrevention(startDate, prevention);
//                model.addAttribute("injectionResultList", injectionResultList);
//                model.addAttribute("vaccineTypeList", vaccineTypeList);
//                model.addAttribute("startDate", startDate);
//                model.addAttribute("prevention", prevention);
//                return "reportInjectionResult";
//            }
//            ///---From and vaccinetype----------------------------------------------------
//            else if (startDate != null && endDate == null && vaccineTypeName != "") {
//                List<InjectionResult> injectionResultList = injectionResultService.findResultsByStartDateAndVaccineTypeName(startDate, vaccineTypeName);
//                model.addAttribute("injectionResultList", injectionResultList);
//                model.addAttribute("vaccineTypeList", vaccineTypeList);
//                model.addAttribute("startDate", startDate);
//                model.addAttribute("vaccineTypeName", vaccineTypeName);
//                return "reportInjectionResult";
//            }
//            ///---From and privention and vaccinetype--------------------------------------
//            else if (startDate != null && endDate == null && vaccineTypeName != "" && prevention != "") {
//                List<InjectionResult> injectionResultList = injectionResultService.findResultsByStartDateAndPreventionAndVaccineTypeName(startDate, prevention, vaccineTypeName);
//                model.addAttribute("injectionResultList", injectionResultList);
//                model.addAttribute("vaccineTypeList", vaccineTypeList);
//                model.addAttribute("startDate", startDate);
//                model.addAttribute("vaccineTypeName", vaccineTypeName);
//                model.addAttribute("prevention", prevention);
//                return "reportInjectionResult";
//            }
//            ///---To and privention-------------------------------------------------------
//            else if (startDate == null && endDate != null && vaccineTypeName == "" && prevention != "") {
//                    List<InjectionResult> injectionResultList = injectionResultService.findResultsByEndDateAndPrevention(endDate, prevention);
//                    model.addAttribute("injectionResultList", injectionResultList);
//                    model.addAttribute("vaccineTypeList", vaccineTypeList);
//                    model.addAttribute("endDate", endDate);
//                    model.addAttribute("prevention", prevention);
//                    return "reportInjectionResult";
//            }
//            ///---To and vaccine Type------------------------------------------------------
//            else if (startDate == null && endDate != null && vaccineTypeName != "" && prevention == "") {
//                    List<InjectionResult> injectionResultList = injectionResultService.findResultsByEndDateAndVaccineTypeName(endDate, vaccineTypeName);
//                    model.addAttribute("injectionResultList", injectionResultList);
//                    model.addAttribute("vaccineTypeList", vaccineTypeList);
//                    model.addAttribute("endDate", endDate);
//                    model.addAttribute("vaccineTypeName", vaccineTypeName);
//                    return "reportInjectionResult";
//            }
//            ///---To and Privention and Vaccine Type----------------------------------------
//            else if (startDate == null && endDate != null && vaccineTypeName != "") {
//                    List<InjectionResult> injectionResultList = injectionResultService.findResultsByEndDateAndPreventionAndVaccineTypeName(endDate, prevention, vaccineTypeName);
//                    model.addAttribute("injectionResultList", injectionResultList);
//                    model.addAttribute("vaccineTypeList", vaccineTypeList);
//                    model.addAttribute("endDate", endDate);
//                    model.addAttribute("vaccineTypeName", vaccineTypeName);
//                    model.addAttribute("prevention", prevention);
//                    return "reportInjectionResult";
//            }
//            //---From To and privention--------------------------------------------
//            else if (startDate != null && endDate != null && prevention !="") {
//                ///--Check date
//                if (endDate.before(startDate)) {
//                    List<InjectionResult> injectionResultList = injectionResultService.findResultsByInjectionDateAndVaccineTypeName(startDate, endDate, vaccineTypeName);
//                    model.addAttribute("injectionResultList", injectionResultList);
//                    model.addAttribute("vaccineTypeList", vaccineTypeList);
//                    model.addAttribute("startDate", startDate);
//                    model.addAttribute("endDate", endDate);
//                    model.addAttribute("error", "To date less than From date");
//                    red.addFlashAttribute("error", "To date less than From date");
//                    return "reportInjectionResult";
//                } else {
//                    List<InjectionResult> injectionResultList = injectionResultService.findResultsByInjectionDateAndPrevention(startDate, endDate, prevention);
//                    model.addAttribute("injectionResultList", injectionResultList);
//                    model.addAttribute("vaccineTypeList", vaccineTypeList);
//                    model.addAttribute("startDate", startDate);
//                    model.addAttribute("endDate", endDate);
//                    model.addAttribute("prevention", prevention);
//                    return "reportInjectionResult";
//                }
//            }
//                ///---From To and Vaccine Type-------------------------------------------
//            else if (startDate != null && endDate != null && vaccineTypeName != "" && prevention == "") {
//                ///--Check date
//                if (endDate.before(startDate)) {
//                    List<InjectionResult> injectionResultList = injectionResultService.findResultsByInjectionDateAndVaccineTypeName(startDate, endDate, vaccineTypeName);
//                    model.addAttribute("injectionResultList", injectionResultList);
//                    model.addAttribute("vaccineTypeList", vaccineTypeList);
//                    model.addAttribute("startDate", startDate);
//                    model.addAttribute("endDate", endDate);
//                    model.addAttribute("error", "To date less than From date");
//                    red.addFlashAttribute("error", "To date less than From date");
//                    return "reportInjectionResult";
//                } else {
//                    List<InjectionResult> injectionResultList = injectionResultService.findResultsByInjectionDateAndVaccineTypeName(startDate, endDate, vaccineTypeName);
//                    model.addAttribute("injectionResultList", injectionResultList);
//                    model.addAttribute("vaccineTypeList", vaccineTypeList);
//                    model.addAttribute("startDate", startDate);
//                    model.addAttribute("endDate", endDate);
//                    model.addAttribute("vaccineTypeName", vaccineTypeName);
//                    return "reportInjectionResult";
//                }
//            }
//            //check date
//            ///---Privention and Type--------------------------------------------
//            else {
//                List<InjectionResult> injectionResultList = injectionResultService.searchResults(startDate, endDate, vaccineTypeName, prevention);
//                model.addAttribute("injectionResultList", injectionResultList);
//                model.addAttribute("vaccineTypeList", vaccineTypeList);
//                model.addAttribute("startDate", startDate);
//                model.addAttribute("endDate", endDate);
//                model.addAttribute("vaccineTypeName", vaccineTypeName);
//                model.addAttribute("prevention", prevention);
//                return "reportInjectionResult";
//            }
        return "reportInjectionResult";
    }
}
