package io.security.corespringsecurity.domain.entity;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;

import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity
@Table(name = "RESOURCES")
@Data
@ToString(exclude = {"roleSet"})
@EntityListeners(value = { AuditingEntityListener.class })
@EqualsAndHashCode(of = "id")
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Resources implements Serializable {

	@Id
	@GeneratedValue
	@Column(name = "resource_id")
	private Long id;

	@Column(name = "resource_name")
	private String resourceName;

	@Column(name = "http_method")
	private String httpMethod;

	@Column(name = "order_num")
	private int orderNum;

	@Column(name = "resource_type")
	private String resourceType;

	@ManyToMany(fetch = FetchType.LAZY)
	@JoinTable(
		// JoinTable 애노테이션을 활용하여 [자원 : 권한 = 다 : 다] 관계의 테이블 간의 연관관계 맵핑용 테이블 생성하여 연관관계를 설정
		name = "role_resources",
		joinColumns = {@JoinColumn(name = "resource_id") },
		inverseJoinColumns = { @JoinColumn(name = "role_id") }
	)
	private Set<Role> roleSet = new HashSet<>();
}
