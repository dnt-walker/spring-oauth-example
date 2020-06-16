package signal9.spring.oauth.authserver.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import signal9.spring.oauth.authserver.dto.LoginUser;
import signal9.spring.oauth.authserver.entity.EndUser;
import signal9.spring.oauth.authserver.repository.UserRepository;

import java.util.Arrays;

@Service
@Qualifier("userDetailService")
public class EndUserDetailService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        EndUser user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("UsernameNotFound [" + username + "]");
        }
        LoginUser loginUser = createUser(user);
        return loginUser;
    }

    private LoginUser createUser(EndUser user) {
        LoginUser loginUser = new LoginUser(user);
        if (loginUser.getUserType().equals("1")) {
            loginUser.setRoles(Arrays.asList("ROLE_ADMIN"));
        } else {
            loginUser.setRoles(Arrays.asList("ROLE_USER"));
        }
        return loginUser;
    }

}