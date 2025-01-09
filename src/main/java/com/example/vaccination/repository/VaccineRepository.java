package com.example.vaccination.repository;

import com.example.vaccination.model.entity.Vaccine;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface VaccineRepository extends JpaRepository<Vaccine, String> {
    List<Vaccine> findAll();
    Optional<Vaccine> findById(String vaccineID);
    Optional<Vaccine> findByVaccineName(String vaccineName);
}
