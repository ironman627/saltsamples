# testing states against heist minions
{% set minion = salt['grains.get']('id') %}

test_state:
  test.configurable_test_state:
    - name: testing a state run from Github
    - changes: True 
    - result: True 
    - comment: State works on {{ minion }}
