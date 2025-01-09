package com.example.vaccination.model.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.format.annotation.DateTimeFormat;

import java.util.Date;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity

@Table(name = "vaccines")
public class Vaccine {
    @Id
    @Column(name = "vaccine_id", length = 36)
    @NotEmpty(message = "Vaccine Code is required!")
    private String vaccineID;

    @Column(name = "contraindication", length = 200)
    private String contraindication;

    @Column(name = "indication", length = 200)
    private String indication;

    @Column(name = "number_of_injection", length = 10)
    @NotEmpty(message = "Number Of Injection is required!")
    private String numberOfInjection;

    @Column(name = "origin", length = 50)
    @NotEmpty(message = "Origin is required!")
    private String origin;

    @Column(name = "description", length = 200)
    private String description;

    @Column(name = "time_begin_next_injection")
    @NotNull(message = "Time Begin Next Injection is required!")
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date timeBeginNextInjection;

    @Column(name = "time_end_next_injection")
    @NotNull(message = "Time End Next Injection is required!")
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date timeEndNextInjection;


    @Column(name = "vaccine_name", length = 100)
    @NotEmpty(message = "Vaccine Name is required!")
    private String vaccineName;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "vacine_type_id")
    @NotNull(message = "Vaccine Type is required!")
    private VaccineType vaccineType;

    @OneToMany(mappedBy = "vaccine_r", cascade = CascadeType.ALL)
    private List<InjectionResult> injectionResults;

    @OneToMany(mappedBy = "vaccine_s", cascade = CascadeType.ALL)
    private List<InjectionSchedule> injectionSchedules;

    @Column(name = "status")
    @NotNull
    private boolean status = true;
}
