package com.example.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by Pavel on 24.12.2016.
 */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "users")
public class User extends Basic implements UserDetails {
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_role",
            joinColumns = {@JoinColumn(name = "user_id")},
            inverseJoinColumns = {@JoinColumn(name = "role_id")})
    private Set<Role> authorities = new HashSet<>();
    @Column(unique = true, nullable = false)
    private String username;
    private String password;
    private boolean accountNonLocked;
    public boolean accountNonExpired;
    public boolean credentialsNonExpired;
    public boolean enabled;

}
