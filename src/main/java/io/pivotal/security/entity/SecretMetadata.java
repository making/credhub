package io.pivotal.security.entity;

import javax.persistence.*;
import java.util.Set;

@Entity
@Table(name = "SecretMetadata")
public class SecretMetadata {
  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  private Long id;

  @Column(unique = true, nullable = false)
  private String name;

  @OneToMany(cascade = CascadeType.ALL, mappedBy="secretMetadata")
  private Set<NamedSecret> namedSecrets;

  public Long getId() {
    return id;
  }

  public void setId(long id) {
    this.id = id;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public Set<NamedSecret> getNamedSecrets() {
    return namedSecrets;
  }

  public void setNamedSecrets(Set<NamedSecret> namedSecrets) {
    this.namedSecrets = namedSecrets;
  }
}
