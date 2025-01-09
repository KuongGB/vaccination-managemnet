package com.example.vaccination.service;

import com.example.vaccination.model.entity.Vaccine;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

public interface VaccineService{
    Vaccine save(Vaccine vaccine);
}
