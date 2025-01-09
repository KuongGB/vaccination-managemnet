package com.example.vaccination.model.dto;

import com.example.vaccination.model.entity.Vaccine;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class InjectionScheduleDto implements Serializable {

    private int injectionScheduleID;

    @Temporal(TemporalType.DATE)
    @NotNull
    private String endDate;

    @NotEmpty
    private String place;
    private int status; //1 = Not yet //2 = Open //3 = Over
    private String note;

    @Temporal(TemporalType.DATE)
    @NotNull
    private String startDate;
    @NotNull
    private Vaccine vaccine_s;
}
