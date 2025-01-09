package com.example.vaccination.service.impl;

import com.example.vaccination.exception.NotFoundException;
import com.example.vaccination.model.entity.InjectionSchedule;
import com.example.vaccination.repository.InjectionScheduleRepository;
import com.example.vaccination.service.InjectionScheduleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class InjectionScheduleServiceImpl implements InjectionScheduleService {

    @Autowired
    private InjectionScheduleRepository injectionScheduleRepository;


    @Override
    public List<InjectionSchedule> findAll() {
        return injectionScheduleRepository.findAll();
    }

    @Override
    public List<InjectionSchedule> findAllByOrderByInjectionScheduleID() {
        return injectionScheduleRepository.findAllByOrderByInjectionScheduleIDDesc();
    }

    @Override
    public InjectionSchedule save(InjectionSchedule injectionSchedule) {
        return injectionScheduleRepository.save(injectionSchedule);
    }

    public InjectionSchedule get(int injectionScheduleID){
        Optional<InjectionSchedule> result = injectionScheduleRepository.findById(injectionScheduleID);
        if(result.isPresent()){
            return result.get();
        }
        throw  new NotFoundException("Could not find any orders with ID" + injectionScheduleID);
    }


}
