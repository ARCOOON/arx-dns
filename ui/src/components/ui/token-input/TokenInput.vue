<script setup lang="ts">
import { computed, ref } from 'vue'
import { ChevronDown, X } from 'lucide-vue-next'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import {
  Popover,
  PopoverAnchor,
  PopoverContent,
} from '@/components/ui/popover'
import { cn } from '@/lib/utils'

const props = withDefaults(
  defineProps<{
    modelValue: string[]
    suggestions?: string[]
    placeholder?: string
    id?: string
    disabled?: boolean
  }>(),
  {
    suggestions: () => [],
    placeholder: 'Type and press Enter…',
    disabled: false,
  },
)

const emit = defineEmits<{
  'update:modelValue': [value: string[]]
}>()

const inputValue = ref('')
const popoverOpen = ref(false)
const anchorRef = ref<HTMLElement | null>(null)

const displaySuggestions = computed(() => {
  const query = inputValue.value.trim().toLowerCase()
  return props.suggestions.filter((item) => {
    if (!query) {
      return true
    }
    return item.toLowerCase().includes(query)
  })
})

function isSelected(item: string): boolean {
  return props.modelValue.some(
    (value) => value.toLowerCase() === item.toLowerCase(),
  )
}

function addToken(raw: string): void {
  const token = raw.trim()
  if (!token) {
    return
  }
  if (isSelected(token)) {
    inputValue.value = ''
    return
  }
  emit('update:modelValue', [...props.modelValue, token])
  inputValue.value = ''
}

function removeToken(index: number): void {
  emit(
    'update:modelValue',
    props.modelValue.filter((_, i) => i !== index),
  )
}

function toggleSuggestion(item: string): void {
  if (isSelected(item)) {
    emit(
      'update:modelValue',
      props.modelValue.filter(
        (value) => value.toLowerCase() !== item.toLowerCase(),
      ),
    )
    return
  }
  emit('update:modelValue', [...props.modelValue, item])
}

function onInputKeydown(event: KeyboardEvent): void {
  if (event.key === 'Enter' || event.key === ',') {
    event.preventDefault()
    addToken(inputValue.value)
    return
  }
  if (event.key === 'Backspace' && !inputValue.value && props.modelValue.length > 0) {
    removeToken(props.modelValue.length - 1)
  }
}

function openPopover(): void {
  if (!props.disabled) {
    popoverOpen.value = true
  }
}

function togglePopover(): void {
  if (props.disabled || props.suggestions.length === 0) {
    return
  }
  popoverOpen.value = !popoverOpen.value
}

function onFocusOutside(event: Event): void {
  const active = document.activeElement
  if (active instanceof Node && anchorRef.value?.contains(active)) {
    event.preventDefault()
  }
}

function onPointerDownOutside(event: Event): void {
  const target = (event as CustomEvent<{ originalEvent: PointerEvent }>).detail
    ?.originalEvent?.target
  if (target instanceof Node && anchorRef.value?.contains(target)) {
    event.preventDefault()
  }
}
</script>

<template>
  <Popover v-model:open="popoverOpen">
    <PopoverAnchor as-child>
      <div ref="anchorRef" :class="cn(
        'flex min-h-9 w-full items-center gap-1 rounded-md border border-input bg-transparent px-2 py-1.5 shadow-sm',
        disabled && 'cursor-not-allowed opacity-60',
      )" @pointerdown.stop>
        <div class="flex min-w-0 flex-1 flex-wrap items-center gap-1.5">
          <Badge v-for="(token, index) in modelValue" :key="`${token}-${index}`" variant="secondary"
            class="gap-1 text-sm font-medium">
            {{ token }}
            <button type="button" class="rounded-sm opacity-70 hover:opacity-100" :disabled="disabled"
              @click="removeToken(index)">
              <X class="size-3" />
            </button>
          </Badge>
          <Input :id="id" v-model="inputValue" :placeholder="modelValue.length === 0 ? placeholder : ''"
            :disabled="disabled"
            class="h-7 min-w-[6rem] flex-1 border-0 bg-transparent px-1 shadow-none focus-visible:ring-0"
            autocomplete="off" @keydown="onInputKeydown" @focus.stop="openPopover" @click.stop="openPopover" />
        </div>
        <Button type="button" variant="ghost" size="icon" class="size-7 shrink-0"
          :disabled="disabled || suggestions.length === 0"
          :aria-label="popoverOpen ? 'Close suggestions' : 'Open suggestions'" @click.stop="togglePopover">
          <ChevronDown :class="cn('size-4 transition-transform', popoverOpen && 'rotate-180')" />
        </Button>
      </div>
    </PopoverAnchor>

    <PopoverContent class="w-[var(--radix-popover-trigger-width)] p-1" align="start" :side-offset="4"
      @open-auto-focus.prevent @close-auto-focus.prevent @focus-outside="onFocusOutside"
      @pointer-down-outside="onPointerDownOutside">
      <div v-if="displaySuggestions.length === 0" class="px-2 py-1.5 text-sm text-muted-foreground">
        No matching suggestions. Press Enter to add a custom value.
      </div>
      <div v-else class="max-h-48 overflow-auto">
        <button v-for="item in displaySuggestions" :key="item" type="button"
          class="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm hover:bg-accent"
          @click.stop="toggleSuggestion(item)">
          <Checkbox :checked="isSelected(item)" class="pointer-events-none" tabindex="-1" />
          <span class="text-sm">{{ item }}</span>
        </button>
      </div>
    </PopoverContent>
  </Popover>
</template>
