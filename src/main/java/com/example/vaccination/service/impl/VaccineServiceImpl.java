package com.example.vaccination.service.impl;

import com.example.vaccination.exception.NotFoundException;
import com.example.vaccination.model.entity.Vaccine;
import com.example.vaccination.repository.VaccineRepository;
import com.example.vaccination.service.VaccineService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;



import java.util.List;

@Service
public class VaccineServiceImpl implements VaccineService {

    @Autowired
    private VaccineRepository repository;

    @Override
    public Vaccine save(Vaccine vaccine){
        return repository.save(vaccine);
    }

    public List<Vaccine> getAllVaccine() {
        return this.repository.findAll();
    }

    public Vaccine addNew(Vaccine p) {
        return repository.save(p);
    }

    public void saveByExcel(List<Vaccine> file) {
        this.repository.saveAll(file);
    }

    public Vaccine findByVaccineName(String name) {
        try {
            return repository.findByVaccineName(name).orElse(null);
        } catch (NotFoundException ex) {
            throw ex;
        }
    }

    public Vaccine findById(String id) {
        try {
            return repository.findById(id).orElse(null);
        } catch (NotFoundException ex) {
            throw ex;
        }
    }
}
