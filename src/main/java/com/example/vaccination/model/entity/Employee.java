package com.example.vaccination.model.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.format.annotation.DateTimeFormat;

import java.util.Date;
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "employees")
public class Employee{

    @Id
    @Column(name = "employee_id", unique = true, length = 36)
    @Pattern(regexp = "^EM[0-9]{1,4}$")
    private String employeeID;

    @Column(name = "address")
    @NotNull
    private String address;

    @Column(name = "date_of_birth")
    @Temporal(TemporalType.DATE)
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    @NotNull(message = "")
    private Date dateOfBirth;

    @Column(name = "email", length = 100, unique = true)
    @NotNull
    private String email;

    @Column(name = "employee_name", length = 100)
    @NotNull
    private String employeeName;

    @Column(name = "gender")
    @NotNull
    private boolean gender;

    @Column(name = "image")
    private String image;

    @Column(name = "password")
    @NotNull
    private String password;

    @Column(name = "phone",unique = true, length = 20)
    @NotNull
    @Pattern(regexp = "^[0-9]+$")
    private String phone;

    @Column(name = "position", length = 100)
    @NotNull
    private String position;

    @Column(name = "username",unique = true)
    @NotNull
    private String username;

    @Column(name = "working_place")
    private String workingPlace;

    @Column(name = "status")
    @NotNull
    private boolean status;
}
