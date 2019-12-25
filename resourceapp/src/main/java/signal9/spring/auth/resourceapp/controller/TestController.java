package signal9.spring.auth.resourceapp.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
public class TestController {
    @GetMapping(value = "/test", produces = {MediaType.APPLICATION_JSON_UTF8_VALUE})
    public ResponseEntity test() {
        Map<String, Object> result = new HashMap<>();

        result.put("message", "xxx");
        result.put("status", "xxx");
        result.put("data", "xxx");

        return ResponseEntity.status(HttpStatus.OK).body(result);
    }
}
