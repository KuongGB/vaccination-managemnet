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

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "customers")
public class Customer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "customer_id")
    private int customerID;

    @Column(name = "address")
    @NotEmpty(message = "Address is required")
    private String address;

    @Column(name = "date_of_birth")
    @Temporal(TemporalType.DATE)
    @NotNull(message = "DateOfBirth is required")
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date dateOfBirth;

    @Column(name = "email",length = 100, unique = true)
    @NotEmpty(message = "Email is required")
    private String email;

    @Column(name = "full_name", length = 100)
    @NotEmpty(message = "Name is required")
    @Pattern(regexp = "^[a-zA-Z\\s]*$")
    private String fullName;

    @Column(name = "gender")
    @NotNull
    private boolean gender;

    @Column(name = "indentify_card", length = 12, unique = true)
    @NotEmpty(message = "Indentify Card is required")
    private String indentifyCard;

    @Column(name = "password")
    @NotEmpty(message = "Password is required")
    private String password;

    @Column(name = "phone", length = 20, unique = true)
    @NotEmpty(message = "Phone number is required")
    private String phone;

    @Column(name = "username", unique = true)
    @NotEmpty(message = "Username is required")
    @Pattern(regexp = "^[a-zA-Z0-9]*$")
    private String username;

    public String getGenderAsString() {
        return gender ? "female" : "male";
    }

    @Override
    public String toString() {
        return "Customer{" +
                "customerID=" + customerID +
                ", address='" + address + '\'' +
                ", dateOfBirth=" + dateOfBirth +
                ", email='" + email + '\'' +
                ", fullName='" + fullName + '\'' +
                ", gender=" + gender +
                ", indentifyCard='" + indentifyCard + '\'' +
                ", password='" + password + '\'' +
                ", phone='" + phone + '\'' +
                ", username='" + username + '\'' +
                '}';
    }
}
