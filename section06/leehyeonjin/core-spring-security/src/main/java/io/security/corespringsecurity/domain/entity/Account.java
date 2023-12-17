package io.security.corespringsecurity.domain.entity;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity
@Data
@ToString(exclude = {"userRoles"})
@Builder
@EqualsAndHashCode(of = "id")
@NoArgsConstructor
@AllArgsConstructor
public class Account implements Serializable {

	@Id
	@GeneratedValue
	private Long id;

	@Column
	private String username;

	@Column
	private String password;

	@Column
	private String email;

	@Column
	private int age;

	// FetchType을 Eager로 설정하여 join 시 필요한 데이터를 한꺼번에 바인딩해서 가져올 수 있도록 함
	@ManyToMany(fetch = FetchType.EAGER, cascade = { CascadeType.ALL })
	@JoinTable(
		// JoinTable 애노테이션을 활용하여 [회원 : 권한 = 다 : 다] 관계의 테이블 간의 연관관계 맵핑용 테이블 생성하여 연관관계를 설정
		name = "account_roles",
		joinColumns = { @JoinColumn(name = "account_id")},
		inverseJoinColumns = { @JoinColumn(name = "role_id") }
	)
	private Set<Role> userRoles = new HashSet<>();
}
