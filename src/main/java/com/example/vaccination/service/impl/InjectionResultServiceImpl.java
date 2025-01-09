package com.example.vaccination.service.impl;

import com.example.vaccination.model.entity.InjectionResult;
import com.example.vaccination.repository.InjectionResultRepository;
import com.example.vaccination.service.InjectionResultService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
public class InjectionResultServiceImpl implements InjectionResultService {

    @Autowired
    private InjectionResultRepository injectionResultRepository;
    @Override
    public List<InjectionResult> findAll() {
        return injectionResultRepository.findAll();
    }
////////////---search
    @Override
    public List<InjectionResult> searchResults(Date startDate, Date endDate, String vaccineTypeName, String prevention) {

            return injectionResultRepository.findResults(startDate, endDate, vaccineTypeName, prevention);
    }

    @Override
    public List<String> count(String yearSelect) {
        return injectionResultRepository.CountInjectionResult(yearSelect);
    }

    @Override
    public InjectionResult addInjectionResult(InjectionResult result){
        return injectionResultRepository.save(result);
    }

    @Override
    public InjectionResult getInjectionResultbyID(int injectionResultID){
        // Add or update new result
        return injectionResultRepository.findById(injectionResultID).orElse(null);
    }
    @Override
    public List<InjectionResult>getALLInjectionResult(){
        // show all result
        return injectionResultRepository.findAll();
    }
    @Override
    public void deleteInjectionResultById(int injectionResultID){
        // delete result follow id
        InjectionResult injectionResult = injectionResultRepository.findById(injectionResultID).orElse(null);
        if (injectionResult !=null){
            injectionResult.setStatus(false);
            injectionResultRepository.save(injectionResult);
        }
    }


    @Override
    public InjectionResult updateInjectionResult(int injectionResultID, InjectionResult updatedResult){
        InjectionResult oldInjection = injectionResultRepository.findByInjectionResultID(injectionResultID);
        injectionResultRepository.saveAndFlush(updatedResult);
        return injectionResultRepository.save(updatedResult);
    }

}
