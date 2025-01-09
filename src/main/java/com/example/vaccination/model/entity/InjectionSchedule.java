package com.example.vaccination.model.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "injection_schedules")
public class InjectionSchedule {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "injection_schedule_id")
    private int injectionScheduleID;

    @Column(name = "end_date")
    @Temporal(TemporalType.DATE)
    @NotNull
    private Date endDate;

    @Column(name = "place", length = 100)
    @NotNull
    private String place;

    @Column(name = "status")
    @NotNull
    private int status; //1 = Not yet //2 = Open //3 = Over

    @Column(name = "note", length = 400)
    private String note;

    @Column(name = "start_date")
    @Temporal(TemporalType.DATE)
    @NotNull
    private Date startDate;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "vacine_id")
    @NotNull
    private Vaccine vaccine_s;

    private String startDateFormatted;
    private String endDateFormatted;
}
