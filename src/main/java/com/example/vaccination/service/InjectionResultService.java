package com.example.vaccination.service;

import com.example.vaccination.model.entity.Customer;
import com.example.vaccination.model.entity.InjectionResult;
import org.springframework.data.repository.query.Param;

import java.util.Date;
import java.util.List;

public interface InjectionResultService {

    //---List all
    List<InjectionResult> findAll();

    ///---Find by all---------------------------------------------------------------------------------
    List<InjectionResult> searchResults(Date startDate, Date endDate, String vaccineTypeName, String prevention);

    InjectionResult addInjectionResult(InjectionResult result);
    InjectionResult updateInjectionResult(int injectionResultID, InjectionResult updateInjection);

    InjectionResult getInjectionResultbyID(int injectionResultID);

    List<InjectionResult> getALLInjectionResult();

    void deleteInjectionResultById(int injectionResultID);
    List<String> count(String yearSelect);

}
