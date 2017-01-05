package com.example.service;

import com.example.model.User;
import org.springframework.stereotype.Service;

/**
 * Created by Pavel on 05.01.2017.
 */
@Service
public interface UserService {
    User findOne (long id) throws Exception;
}
