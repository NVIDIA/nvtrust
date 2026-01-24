package policy
import future.keywords.every

default nv_match := false
nv_match {
  every result in input {
    result.secboot
    result.dbgstat == "disabled"
  }
}