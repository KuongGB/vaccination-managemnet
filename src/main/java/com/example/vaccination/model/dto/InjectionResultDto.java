package com.example.vaccination.model.dto;

import com.example.vaccination.model.entity.Customer;
import com.example.vaccination.model.entity.Vaccine;
import jakarta.persistence.*;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class InjectionResultDto implements Serializable {

    private int injectionResultID;

    @NotNull
    private String injectionDate;

    @NotNull
    private String injectionPlace;

    @NotNull
    private String nextInjectionDate;

    @NotNull
    private int numberOfInjection;

    @NotNull
    private String prevention;

    @NotNull
    private Customer customer;

    @NotNull
    private Vaccine vaccine_r;
}
