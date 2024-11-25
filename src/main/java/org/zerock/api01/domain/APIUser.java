package org.zerock.api01.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.*;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Entity
public class APIUser {

    @Id
    private String mid;
    private String mpw;

    public void changePw(String mpw) {
        this.mpw = mpw;
    }
}
