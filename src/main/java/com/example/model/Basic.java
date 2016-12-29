package com.example.model;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.MappedSuperclass;

/**
 * Created by Pavel on 25.12.2016.
 */
@Getter
@Setter
@MappedSuperclass
public class Basic {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
}
