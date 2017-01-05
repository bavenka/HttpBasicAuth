package com.example.service.impl;

import com.example.model.User;
import com.example.repository.UserRepository;
import com.example.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;

/**
 * Created by Pavel on 05.01.2017.
 */
@Component
@Transactional
public class UserServiceImpl implements UserService{

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private UserRepository userRepository;

    @Override
    public User findOne(long id) throws Exception {
        logger.info("Fetching User with id {}", id);
        return userRepository.findOne(id).orElseThrow(() ->
                new Exception("User with id " + id + " not found."));
    }
}
